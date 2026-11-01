import { Component, computed, signal, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { request } from './api-client';
import { SessionEpoch, isUnauthorized } from './session-epoch';
import { deviceDisplayRole, deviceDisplayType, deviceDisplayOS, deviceDisplayOSSymbol, isDeviceDisplayRole } from './device-presentation';

type View = 'workspace'|'hardware'|'browser'|'activity'|'access'|'files';
type Device = {
 id:string; display_name:string; hostname?:string; platform?:string; architecture?:string;
 status?:string; connected?:boolean; revoked_at?:string|null; is_owner?:boolean; approved_at?:string; agent_protocol_version?:string; key_generation?:number|string; recommended_agent_version?:string; agent_update_available?:boolean;
 permission_profile?:string; access_max_permission_profile?:string; agent_version?:string; active_jobs?:any[];
 last_seen?:number|string; managed_by_me?:boolean; capabilities?:Record<string,any>; grants?:any[];
};
type Inspect = {system_info?:Record<string,any>;system_metrics?:Record<string,any>};
type Pending = {id:string;metadata?:Record<string,any>;verification_code?:string;expires_at?:number};
type BrowserSession = {client_id:string; session_id?:string;state?:string;title?:string};
@Component({
 selector:'app-root', standalone:true, imports:[CommonModule,FormsModule],
 templateUrl:'./app.html'
})
export class App implements OnInit, OnDestroy {
 loggedIn=signal(false); loading=signal(true); error=signal(''); notice=signal('');
 session=signal<any>(null); devices=signal<Device[]>([]); pending=signal<Pending[]>([]);
 accountMenu=signal(false); logoutBusy=signal(false); syncHealthy=signal(true); syncing=signal(false); lastSynced=signal(0);
 jobsById=signal<Record<string,number>>({}); anyWorking=computed(()=>Object.values(this.jobsById()).some(n=>n>0));
 roleOverrides=signal<Record<string,string>>({});

 selected=signal(0); view=signal<View>('workspace'); inspect=signal<Inspect|null>(null);
 activity=signal<any[]>([]); activityLoading=signal(false); activityLoaded=signal(false); activityError=signal('');
 activityFilter=signal(''); activityPage=signal(1); readonly activityPageSize=12;
 browsers=signal<BrowserSession[]>([]);
 browserClient=signal(''); browserFrame=signal(''); browserPage=signal(''); browserAction=signal(''); browserState=signal('idle'); browserBusy=signal(false);
 browserSequence=-1; browserEpoch=0; browserPaused=signal(false); browserPrivateLink=signal(''); 
 overlay=signal<'none'|'add'|'palette'|'confirm'|'pending'|'settings'|'permission-confirm'|'permission-reauthorize'|'grant-confirm'|'restore-confirm'|'audit'>('none');
 commandQuery=signal(''); typedCode=''; grantMyself=true; confirmName=''; confirmation: (()=>Promise<void>)|null=null;
 search=signal(''); helperAvailable=signal(false); installChecked=signal(false);
 permissionChoice='STANDARD'; userIntent=''; installPrompt:any=null;
 managerError=signal(false); permissionBusy=signal(false); permissionError=signal(''); pendingPermission:{deviceId:string;level:string;expected_profile:string|null;expected_grant:string|null}|null=null; renameValue=''; grantSubject=''; grantLevel='STANDARD'; initialPermission='FULL_CONTROL';
 selectedGrantSubject=''; grantToRemove=''; awaitingGrantRemoval=false;
 audit=signal<any[]>([]); auditBusy=signal(false);
 detail=signal<Device|null>(null); detailedDeviceId='';
 capabilities=['filesystem','shell','process','git','docker','services','packages','system_power','browser','desktop','screen','keyboard','mouse','clipboard','agent_update','privileged_helper'];
 private staleInspect=0; private staleActivity=0;
 private timer:any; private metricsTimer:any; private browserTimer:any; private fastTimer:any; private activityTimer:any; private browserSessionsTimer:any;
 private fastBusy=false; private jobsBusy=false; private jobsTimer:any; private destroyed=false;
 private readonly sessionEpoch=new SessionEpoch();

 selectedDevice=computed(()=>this.devices()[this.selected()] ?? null);
 filteredActivity=computed(()=>{const filter=this.activityFilter().trim().toLowerCase();return filter?this.activity().filter(e=>(this.dataItem(e)+' '+this.dataDetail(e)+' '+String(e.status||'')).toLowerCase().includes(filter)):this.activity();});
 pageCount=computed(()=>Math.max(1,Math.ceil(this.filteredActivity().length/this.activityPageSize)));
 pagedActivity=computed(()=>this.filteredActivity().slice((this.activityPage()-1)*this.activityPageSize,this.activityPage()*this.activityPageSize));
 activeOperations=computed(()=>this.jobsById()[this.selectedDevice()?.id||'']||0);
 logoFor(status:'online'|'offline'|'loading'|'working'|'attention'|'completed'|'idle'){return '/brand/octopus-'+status+'.svg?v=20261029-v8';}
 deviceOnline(d:Device){return typeof d.connected==='boolean'?d.connected:d.status==='online';}
 deviceWorking(d:Device){return this.deviceOnline(d)&&(this.jobsById()[d.id]||0)>0;}
 devicePermission(d:Device){return this.levelName(d.permission_profile||null);}
 deviceRole(d:Device){return deviceDisplayRole(d, this.roleOverrides());}
 deviceType(d:Device){return deviceDisplayType(this.deviceRole(d));}
 deviceOS(d:Device){return deviceDisplayOS(d.platform);}
 roleSelection(d:Device){return this.roleOverrides()[d.id]||'auto';}
 setDeviceRole(d:Device,role:string){
   if(role!=='auto'&&!isDeviceDisplayRole(role))return;
   const next={...this.roleOverrides()};if(role==='auto')delete next[d.id];else next[d.id]=role;
   this.roleOverrides.set(next);
   try{localStorage.setItem('commandcore:display-types:'+String(this.session()?.subject||'local'),JSON.stringify(next));}catch{}
 }
 loadDeviceRoles(){try{
  const raw=localStorage.getItem('commandcore:display-types:'+String(this.session()?.subject||'local'));
  if(raw){const obj=JSON.parse(raw);if(obj&&typeof obj==='object'&&!Array.isArray(obj))this.roleOverrides.set(obj);}
 }catch{}
 }
 osSymbol(d:Device){return deviceDisplayOSSymbol(d.platform);}

 resetActivity(){this.activityPage.set(1);this.activityFilter.set('');this.activityLoaded.set(false);this.activity.set([]);this.activityError.set('');}
 activitySearch(v:string){this.activityFilter.set(v);this.activityPage.set(1);}

 onlineCount=computed(()=>this.devices().filter(d=>this.deviceOnline(d)).length);
 displayDevices=computed(()=>this.devices().filter(d=>!d.revoked_at));
 selectedMetrics=computed(()=>this.inspect()?.system_metrics||null);
 selectedInfo=computed(()=>this.inspect()?.system_info||null);
 oauthProfile=computed(()=>{
   const session=this.session();
   if(['panel-cookie','bootstrap-bearer'].includes(session?.auth_kind))return 'NOT_APPLICABLE';
   const scopes=Array.isArray(session?.scopes)?session.scopes:[];
   return scopes.includes('commandcore:full')?'FULL_CONTROL':scopes.includes('commandcore:standard')?'STANDARD':scopes.includes('commandcore:read')?'READ_ONLY':'NO_ACCESS';
 });
 ownGrant=computed(()=>{
  const d=this.selectedDevice();if(!d)return null;
  const grant=Array.isArray(d.grants)?d.grants.find((g:any)=>g.subject===this.session()?.subject)?.max_permission_profile:null;
  if(d.managed_by_me&&Array.isArray(d.grants)&&grant)return grant;
  return grant||d.access_max_permission_profile||(d.is_owner?'FULL_CONTROL':null);
 });
 localCeiling=computed(()=>this.selectedDevice()?.capabilities?.['local_max_permission_profile']||'STANDARD');
 helperReady=computed(()=>this.selectedDevice()?.capabilities?.['privileged_helper']===true);
 localFullReady=computed(()=>this.localCeiling()==='FULL_CONTROL'&&this.helperReady()&&!!this.selectedDevice()?.connected);
 fullEligible=computed(()=>this.localFullReady()&&['FULL_CONTROL','NOT_APPLICABLE'].includes(this.oauthProfile()));
 oauthFullReady=computed(()=>['FULL_CONTROL','NOT_APPLICABLE'].includes(this.oauthProfile()));
 oauthStandardReady=computed(()=>['STANDARD','FULL_CONTROL','NOT_APPLICABLE'].includes(this.oauthProfile()));
 permissionOAuthReady(level:string){return level==='FULL_CONTROL'?this.oauthFullReady():this.oauthStandardReady();}

 permissionLayers=computed(()=>{
   const d=this.selectedDevice();if(!d)return [];
   return [
     {name:'OAuth scope',value:this.oauthProfile(),help:this.oauthProfile()==='NOT_APPLICABLE'?'Recovery session; OAuth scope does not apply.':'The active web session limits actions; reconnect with Full Control scope if necessary.'},
     {name:'Server policy',value:d.permission_profile||'UNKNOWN',help:'Configured permission profile for this device; may also restrict other accounts.'},
     {name:'Account grant',value:this.ownGrant()||'NOT_GRANTED',help:d.is_owner?'Owner permission.':'The current account’s explicit device grant.'},
     {name:'Local ceiling',value:this.localCeiling(),help:this.helperReady()?'Helper available; local ceiling is still authoritative.':'Full Control requires a locally approved, healthy privileged helper.'}
   ];
 });
 effectivePermission=computed(()=>{
   const d=this.selectedDevice();if(!d)return 'UNKNOWN';
   const ranks:Record<string,number>={READ_ONLY:0,STANDARD:1,FULL_CONTROL:2};
   if(!this.ownGrant()&&d.managed_by_me&&!d.is_owner)return 'NOT_GRANTED';
   const layers=this.permissionLayers().map(l=>l.value).filter(v=>v!=='NOT_APPLICABLE');
   if(layers.some(v=>v==='NO_ACCESS'))return 'NO_ACCESS';
   if(layers.some(v=>!(v in ranks)))return 'UNKNOWN';
   return Object.keys(ranks).find(k=>ranks[k]===Math.min(...layers.map(v=>ranks[v])))||'UNKNOWN';
 });
 canFull=computed(()=>this.localFullReady()&&!!this.selectedDevice()?.managed_by_me);
 canStandard=computed(()=>this.localCeiling()!=='READ_ONLY');
 myGrantNeedsRestore=computed(()=>!!this.selectedDevice()?.managed_by_me&&!this.ownGrant());
 updateAvailable=computed(()=>this.selectedDevice()?.agent_update_available===true);
 tabs:{key:View;label:string;icon:string}[]=[
  {key:'workspace',label:'Workspace',icon:'◈'}, {key:'hardware',label:'Hardware',icon:'▤'},
  {key:'browser',label:'Browser',icon:'◎'},{key:'activity',label:'Activity',icon:'≋'},
  {key:'access',label:'Access',icon:'◇'},{key:'files',label:'Files',icon:'▦'}
 ];
 constructor(){
  window.addEventListener('keydown',this.onKey);
  window.addEventListener('beforeinstallprompt',this.onInstall as any);
 }
 ngOnInit(){void this.init();}
 ngOnDestroy(){this.destroyed=true;this.sessionEpoch.end();clearInterval(this.timer);clearInterval(this.fastTimer);clearInterval(this.jobsTimer);clearInterval(this.activityTimer);clearInterval(this.browserSessionsTimer);clearInterval(this.metricsTimer);clearInterval(this.browserTimer);document.removeEventListener('visibilitychange',this.onResume);window.removeEventListener('focus',this.onResume);window.removeEventListener('online',this.onResume);window.removeEventListener('keydown',this.onKey);window.removeEventListener('beforeinstallprompt',this.onInstall as any);}
 private onKey=(event:KeyboardEvent)=>{if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='k'){event.preventDefault();this.overlay.set('palette');}
  if(event.key==='Escape'){this.overlay.set('none');this.accountMenu.set(false);return;}
  if(this.overlay()!=='none'&&event.key==='Tab'){
    const panel=document.querySelector('.sheet, .command-palette');
    const focusable=Array.from(panel?.querySelectorAll<HTMLElement>('button:not([disabled]),a[href],input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex=\"-1\"])')||[]).filter(el=>el.getClientRects().length>0);
    if(focusable.length){const at=focusable.indexOf(document.activeElement as HTMLElement);
      if(at<0||(event.shiftKey&&at===0)||(!event.shiftKey&&at===focusable.length-1)){
        event.preventDefault();(event.shiftKey?focusable[focusable.length-1]:focusable[0]).focus();
      }
    }
    return;
  }
  if(this.accountMenu())this.accountMenu.set(false);
  if(this.overlay()!=='none'||/INPUT|TEXTAREA|SELECT/.test((event.target as HTMLElement)?.tagName||''))return;
  if(event.key==='ArrowRight')this.move(1);if(event.key==='ArrowLeft')this.move(-1);
 };
 private onInstall=(event:Event)=>{event.preventDefault();this.installPrompt=event;};
 private onResume=()=>{if(!document.hidden&&this.loggedIn()){void this.refreshDeviceStates();void this.refresh(true);void this.loadSelectedJobs();if(this.view()==='activity'||this.view()==='workspace'||this.view()==='files')void this.loadActivity();if(this.view()==='browser')void this.loadBrowserSessions();}};
 toggleAccount(){this.overlay.set('none');this.accountMenu.update(x=>!x);}

 mobileFocusWorkspace(){if(typeof window!=='undefined'&&typeof window.matchMedia==='function'&&window.matchMedia('(max-width:720px)').matches){requestAnimationFrame(()=>document.querySelector('.workspace-frame')?.scrollIntoView({behavior:window.matchMedia('(prefers-reduced-motion:reduce)').matches?'instant':'smooth',block:'start'}));}}
 async installApp(){if(this.installPrompt){await this.installPrompt.prompt();this.installPrompt=null;}else this.message('Use your browser menu to add CommandCore to your home screen.');}
 /** Clear user-specific cached data immediately when authentication ends. */
 private endSession(message=''){
  this.sessionEpoch.end();
  this.staleInspect++;this.staleActivity++;this.browserEpoch++;
  this.loggedIn.set(false);this.session.set(null);this.error.set(message);
  this.devices.set([]);this.pending.set([]);this.detail.set(null);this.inspect.set(null);
  this.activity.set([]);this.activityLoaded.set(false);this.activityError.set('');
  this.browsers.set([]);this.browserClient.set('');this.browserFrame.set('');
  this.browserPrivateLink.set('');this.browserPage.set('');this.browserAction.set('');
  this.browserState.set('idle');this.browserBusy.set(false);this.browserSequence=-1;
  this.jobsById.set({});this.audit.set([]);this.roleOverrides.set({});
  this.pendingPermission=null;this.confirmation=null;this.typedCode='';this.grantSubject='';
  this.grantToRemove='';this.selectedGrantSubject='';this.commandQuery.set('');
  this.notice.set('');this.selected.set(0);this.activityLoading.set(false);
  this.auditBusy.set(false);this.permissionBusy.set(false);
  this.accountMenu.set(false);this.overlay.set('none');this.syncHealthy.set(false);
 }
 async init(){
  this.loading.set(true);try{const session=await request('/api/session');if(this.destroyed)return;this.sessionEpoch.start();this.session.set(session);this.loggedIn.set(true);this.error.set('');this.loadDeviceRoles();await this.refresh();if(!this.loggedIn())return;await this.loadSelectedJobs();if(!this.loggedIn())return;this.restorePermissionIntent();
   this.fastTimer=setInterval(()=>{if(!document.hidden)void this.refreshDeviceStates();},4000);
   this.timer=setInterval(()=>{if(this.loggedIn()&&!document.hidden)void this.refresh(true);},16000);
   this.activityTimer=setInterval(()=>{if(this.loggedIn()&&!document.hidden&&['workspace','activity','files'].includes(this.view()))void this.loadActivity();if(this.loggedIn()&&!document.hidden)void this.loadSelectedJobs();},5000);
   this.jobsTimer=setInterval(()=>{if(!document.hidden)void this.refreshActiveJobs();},8000);
   void this.refreshActiveJobs();
   this.metricsTimer=setInterval(()=>{if(this.loggedIn()&&!document.hidden&&(this.view()==='workspace'||this.view()==='hardware'))void this.loadInspect();},45000);
   this.browserSessionsTimer=setInterval(()=>{if(this.loggedIn()&&!document.hidden&&this.view()==='browser')void this.loadBrowserSessions();},10000);
   this.browserTimer=setInterval(()=>{if(this.loggedIn()&&!document.hidden&&this.view()==='browser'&&!this.browserPaused())void this.refreshBrowserFrame();},2800);
   document.addEventListener('visibilitychange',this.onResume);window.addEventListener('focus',this.onResume);window.addEventListener('online',this.onResume);
  }catch(e){if(isUnauthorized(e))this.endSession('Session expired. Sign in again.');else if(!this.loggedIn())this.error.set(this.err(e));else this.message(this.err(e));}finally{this.loading.set(false);}
 }
 async signOut(){
   if(this.logoutBusy())return;this.logoutBusy.set(true);
   try{
    await request('/api/session','DELETE');this.endSession();
    location.replace('/');
   }catch(e){this.message('Sign out failed: '+this.err(e));this.logoutBusy.set(false);}
 }
 async refreshDeviceStates(){
  if(this.fastBusy||!this.loggedIn())return;const sessionVersion=this.sessionEpoch.snapshot();this.fastBusy=true;this.syncing.set(true);
  try{
   const result=await request<{devices:Device[]}>('/api/devices');
   if(!this.sessionEpoch.isCurrent(sessionVersion))return;
   const previous=this.devices();const retained=new Map(previous.map(d=>[d.id,d]));
   const updated:Device[]=(result.devices||[]).filter(d=>!d.revoked_at).map(d=>({...retained.get(d.id),...d,managed_by_me:retained.get(d.id)?.managed_by_me||d.managed_by_me,grants:retained.get(d.id)?.grants||d.grants}));
   for(const old of previous){if(old.managed_by_me&&!old.revoked_at&&!updated.some(d=>d.id===old.id))updated.push(old);}
   const prior=this.selectedDevice()?.id;this.devices.set(updated);if(prior){const index=updated.findIndex(d=>d.id===prior);if(index>=0)this.selected.set(index);else this.selected.set(0);}
   this.syncHealthy.set(true);this.lastSynced.set(Date.now());
  }catch(e){if(this.sessionEpoch.isCurrent(sessionVersion)){this.syncHealthy.set(false);if(isUnauthorized(e))this.endSession('Session expired. Sign in again.');}}
  finally{this.fastBusy=false;this.syncing.set(false);}
 }
 async refreshActiveJobs(){
   if(this.jobsBusy||!this.loggedIn())return;const sessionVersion=this.sessionEpoch.snapshot();this.jobsBusy=true;
   const candidates=this.devices().filter(d=>this.deviceOnline(d)).slice(0,6);
   try{
     const results=await Promise.allSettled(candidates.map(d=>request<{device:Device}>('/api/devices/'+encodeURIComponent(d.id))));
     if(!this.sessionEpoch.isCurrent(sessionVersion))return;
     const next={...this.jobsById()};
     candidates.forEach((d,i)=>{const result=results[i];next[d.id]=result.status==='fulfilled'&&Array.isArray(result.value.device?.active_jobs)?result.value.device.active_jobs.length:0;});
     for(const d of this.devices())if(!this.deviceOnline(d))next[d.id]=0;
     this.jobsById.set(next);
   }finally{this.jobsBusy=false;}
 }
 async loadSelectedJobs(){
   const sessionVersion=this.sessionEpoch.snapshot();
   const d=this.selectedDevice();if(!d||!this.deviceOnline(d)){this.detail.set(null);return;}
   try{const payload=await request<{device:Device}>('/api/devices/'+encodeURIComponent(d.id));if(this.sessionEpoch.isCurrent(sessionVersion)&&this.selectedDevice()?.id===d.id){this.detail.set(payload.device);this.jobsById.update(map=>({...map,[d.id]:Array.isArray(payload.device.active_jobs)?payload.device.active_jobs.length:0}));}}
   catch{ /* a temporarily unavailable detail endpoint must not invent an active job */if(this.sessionEpoch.isCurrent(sessionVersion)&&this.selectedDevice()?.id===d.id){this.detail.set(null);this.jobsById.update(map=>({...map,[d.id]:0}));} }
 }

 async refresh(quiet=false){
  const sessionVersion=this.sessionEpoch.snapshot();
  if(!this.sessionEpoch.isCurrent(sessionVersion))return;
  try{
   const [d,m,p]=await Promise.all([
    request<{devices:Device[]}>('/api/devices'),
    request<{devices:Device[]}>('/api/managed-devices').then(v=>{this.managerError.set(false);return v;}).catch(()=>{this.managerError.set(true);return {devices:[]};}),
    request<{enrollments:Pending[]}>('/api/enrollment/pending').catch(()=>({enrollments:[]}))
   ]);
   const merged=new Map<string,Device>();
   for(const device of d.devices||[])merged.set(device.id,device);
   for(const item of m.devices||[])merged.set(item.id,{...(merged.get(item.id)||{}),...item,managed_by_me:true});
   const list=Array.from(merged.values()).filter(x=>!x.revoked_at);
   if(!this.sessionEpoch.isCurrent(sessionVersion))return;
   const prior=this.selectedDevice()?.id;
   this.devices.set(list);this.pending.set(p.enrollments||[]);
   if(prior){const idx=list.findIndex(x=>x.id===prior);this.selected.set(idx>=0?idx:0);}
   if(!quiet){this.lastSynced.set(Date.now());this.syncHealthy.set(true);this.permissionChoice=this.ownGrant()||'STANDARD';this.renameValue=this.selectedDevice()?.display_name||'';if(this.view()==='workspace'||this.view()==='hardware')await this.loadInspect();if(this.view()==='activity'||this.view()==='workspace')await this.loadActivity();await this.loadSelectedJobs();}
  }catch(e){if(!this.sessionEpoch.isCurrent(sessionVersion))return;if(isUnauthorized(e))this.endSession('Your session expired. Sign in again to continue.');else if(!quiet)this.message('Devices: '+this.err(e));}
 }
 async move(step:number){const n=this.devices().length;if(!n)return;await this.select((this.selected()+step+n)%n);}
 async select(i:number){this.selected.set(i);this.detail.set(null);this.inspect.set(null);this.resetActivity();this.browserFrame.set('');this.permissionError.set('');this.permissionChoice=this.ownGrant()||'STANDARD';this.renameValue=this.selectedDevice()?.display_name||'';this.mobileFocusWorkspace();if(this.view()==='workspace'||this.view()==='hardware')await this.loadInspect();if(this.view()==='activity'||this.view()==='workspace')await this.loadActivity();await this.loadSelectedJobs();}
 async show(view:View){this.view.set(view);this.accountMenu.set(false);this.overlay.set('none');this.mobileFocusWorkspace();if(view==='hardware'||(view==='workspace'&&!this.inspect()))await this.loadInspect();if(view==='access')this.onAccess();if(view==='activity'||view==='workspace'||view==='files')await this.loadActivity();if(view==='browser')await this.loadBrowserSessions();}
 async loadInspect(){const sessionVersion=this.sessionEpoch.snapshot();const device=this.selectedDevice();if(!device)return;if(!this.deviceOnline(device)){this.inspect.set(null);return;}
  const generation=++this.staleInspect;
  try{const result=await request<Inspect>('/api/devices/'+encodeURIComponent(device.id)+'/inspect','POST');if(this.sessionEpoch.isCurrent(sessionVersion)&&generation===this.staleInspect&&this.selectedDevice()?.id===device.id)this.inspect.set(result);}catch{if(this.sessionEpoch.isCurrent(sessionVersion)&&generation===this.staleInspect)this.inspect.set(null);}
 }
 fileActivity=computed(()=>this.activity().filter((e:any)=>/^(fs\.|transfer\.|file\.)/i.test(String(e.tool||e.operation||''))).slice(0,12));
 async loadActivity(){const sessionVersion=this.sessionEpoch.snapshot();const d=this.selectedDevice();if(!d)return;const generation=++this.staleActivity;const first=!this.activityLoaded();if(first)this.activityLoading.set(true);
  try{const result=await request<any>('/api/devices/'+encodeURIComponent(d.id)+'/activity');if(!this.sessionEpoch.isCurrent(sessionVersion)||generation!==this.staleActivity||this.selectedDevice()?.id!==d.id)return;
  this.activityError.set('');this.activityLoaded.set(true);
  this.activity.set(Array.isArray(result)?result:Array.isArray(result.events)?result.events:Array.isArray(result.activity)?result.activity:Array.isArray(result.rows)?result.rows:[]);
  this.activityPage.set(Math.min(this.activityPage(),Math.max(1,Math.ceil(this.filteredActivity().length/this.activityPageSize))));
 }catch(e){if(this.sessionEpoch.isCurrent(sessionVersion)&&generation===this.staleActivity){this.activityError.set(this.err(e));this.activityLoaded.set(true);}}finally{if(this.sessionEpoch.isCurrent(sessionVersion)&&generation===this.staleActivity)this.activityLoading.set(false);}}
 async loadBrowserSessions(){const sessionVersion=this.sessionEpoch.snapshot();if(!this.sessionEpoch.isCurrent(sessionVersion))return;try{const result=await request<any>('/api/browser/sessions');if(!this.sessionEpoch.isCurrent(sessionVersion))return;this.browsers.set(result.sessions||[]);
  const existing=this.browserClient();const next=(result.sessions||[]).find((s:BrowserSession)=>s.client_id===existing)?.client_id || result.sessions?.[0]?.client_id || '';
  if(next!==existing){this.browserEpoch++;this.browserClient.set(next);this.browserSequence=-1;this.browserFrame.set('');this.browserPrivateLink.set('');this.browserPage.set('');}
  if(next)await this.refreshBrowserFrame();else {this.browserFrame.set('');this.browserPrivateLink.set('');this.browserState.set(result.enabled===false?'unavailable':'empty');}
 }catch(e){if(this.sessionEpoch.isCurrent(sessionVersion)){this.browsers.set([]);this.browserState.set('unavailable');this.message(this.err(e));}}}
 async chooseBrowser(id:string){this.browserEpoch++;this.browserClient.set(id);this.browserSequence=-1;this.browserFrame.set('');this.browserPrivateLink.set('');this.browserPage.set('');await this.refreshBrowserFrame();}
 async refreshBrowserFrame(){const sessionVersion=this.sessionEpoch.snapshot();const id=this.browserClient(),epoch=this.browserEpoch;if(!id||this.browserPaused()||this.browserState()==='requesting_human')return;
  try{const data=await request<any>('/api/browser/frame?client_id='+encodeURIComponent(id)+'&after_sequence='+this.browserSequence);
   if(!this.sessionEpoch.isCurrent(sessionVersion)||this.browserClient()!==id||this.browserEpoch!==epoch||this.browserPaused())return;const state=String(data.state||'ready');this.browserState.set(state);this.browserBusy.set(data.busy===true);
   if(state==='awaiting_human'){this.browserFrame.set('');this.browserPage.set('Private human control is active');return;}
   this.browserPrivateLink.set('');
   if(data.changed&&typeof data.screenshot_base64==='string'&&/^[A-Za-z0-9+/=]+$/.test(data.screenshot_base64)){
    this.browserFrame.set('data:image/png;base64,'+data.screenshot_base64);
    this.browserSequence=Number.isInteger(data.sequence)?data.sequence:this.browserSequence;
    this.browserPage.set(String(data.title||'')+(data.url?' · '+String(data.url):''));
   }
   this.browserAction.set(String(data.action||''));
  }catch(e){if(!this.sessionEpoch.isCurrent(sessionVersion)||this.browserClient()!==id||this.browserEpoch!==epoch||this.browserPaused())return;this.browserState.set('unavailable');this.message('Browser: '+this.err(e));}
 }
 async handoff(){const sessionVersion=this.sessionEpoch.snapshot();if(!this.sessionEpoch.isCurrent(sessionVersion)||!this.browserClient()||this.browserState()==='awaiting_human'||this.browserState()==='requesting_human')return;const id=this.browserClient(),epoch=++this.browserEpoch;this.browserFrame.set('');this.browserState.set('requesting_human');this.browserBusy.set(true);try{
  const data=await request<any>('/api/browser/handoff','POST',{client_id:id});
  if(!this.sessionEpoch.isCurrent(sessionVersion)||this.browserClient()!==id||this.browserEpoch!==epoch)return;
  if(typeof data.handoff_path!=='string'||!/^\/browser\/console\/[A-Za-z0-9_-]+$/.test(data.handoff_path))throw Error('Invalid private-control URL');
  this.browserPrivateLink.set(data.handoff_path);this.browserFrame.set('');this.browserState.set('awaiting_human');this.browserBusy.set(false);
  this.message('Private control is ready. Open it to sign in or approve, then resume AI control there.');
 }catch(e){if(this.sessionEpoch.isCurrent(sessionVersion)&&this.browserClient()===id&&this.browserEpoch===epoch){this.browserState.set('unavailable');this.browserBusy.set(false);void this.loadBrowserSessions();}if(this.sessionEpoch.isCurrent(sessionVersion))this.message(this.err(e));}}
 async checkInstall(){this.installChecked.set(false);try{const res=await fetch('/install/linux-ready',{method:'HEAD',credentials:'same-origin',cache:'no-store'});this.helperAvailable.set(res.ok);}catch{this.helperAvailable.set(false);}this.installChecked.set(true);}
 openAdd(){this.overlay.set('add');void this.checkInstall();}
 openPending(){this.initialPermission=this.oauthFullReady()?'FULL_CONTROL':'STANDARD';this.overlay.set('pending');void this.refresh(true);}
 cmd(kind:'full'|'standard'='full'):string{return kind==='full'?'bash -o pipefail -c \x27curl -fsSL '+location.origin+'/install/linux-ready | bash\x27':'curl -fsSL '+location.origin+'/install/linux | sh';}
 async copy(value:string){try{await navigator.clipboard.writeText(value);this.message('Copied to clipboard');}catch{this.message('Copy unavailable. Select the command and copy manually.');}}
 async decide(enrollment:Pending,approve:boolean){
  if(!/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(this.typedCode.trim().toUpperCase())){this.message('Enter the 9-character verification code displayed by your device.');return;}
  if(approve&&this.initialPermission==='FULL_CONTROL'&&!this.oauthFullReady()){this.message('Full Control enrollment requires Full Control OAuth. Reconnect with Full Control or select Standard.');return;}
  try{await request('/api/enrollment/pending/'+encodeURIComponent(enrollment.id)+'/decision','POST',{code:this.typedCode.trim().toUpperCase(),approve,grant_to_me:this.grantMyself,initial_permission:approve?this.initialPermission:'STANDARD'});
  this.typedCode='';this.message(approve?'Enrollment approved; wait for the device to connect.':'Enrollment rejected.');this.overlay.set('none');await this.refresh();
  }catch(e){this.message(this.err(e));}
 }
 choosePending(e:Pending){this.userIntent=e.id;this.typedCode='';this.overlay.set('pending');}
 async grantPermission(){
  const d=this.selectedDevice();if(!d?.managed_by_me||this.permissionBusy())return;
  if(this.permissionChoice==='FULL_CONTROL'&&!this.localFullReady()){this.permissionError.set('Full Control is not available locally: the device must be online, its local ceiling must be FULL_CONTROL and its privileged helper must be healthy.');return;}
  if(!this.permissionOAuthReady(this.permissionChoice)){this.overlay.set('permission-reauthorize');return;}
  if(this.permissionChoice==='STANDARD'&&!this.canStandard()){this.permissionError.set('The device local ceiling only allows Read Only.');return;}
  this.permissionError.set('');
  this.pendingPermission={deviceId:d.id,level:this.permissionChoice,expected_profile:d.permission_profile||null,expected_grant:(d.grants||[]).find((g:any)=>g.subject===this.session()?.subject)?.max_permission_profile||null};
  this.overlay.set('permission-confirm');
 }
 beginFullOAuthReconnection(){this.permissionChoice='FULL_CONTROL';this.beginPermissionOAuthReconnection();}
 beginPermissionOAuthReconnection(){
  const d=this.selectedDevice();
  if(!d||!d.managed_by_me)return;
  const level=this.permissionChoice;
  if(level==='FULL_CONTROL'&&!this.localFullReady())return;
  const access=level==='FULL_CONTROL'?'full':'standard';
  try{sessionStorage.setItem('commandcore:pending-permission-reauthorize',JSON.stringify({deviceId:d.id,subject:this.session()?.subject,level,expiresAt:Date.now()+15*60*1000}));}catch{}
  window.location.assign('/auth/login?access='+access);
 }
 restorePermissionIntent(){
  let raw:string|null=null;
  try{raw=sessionStorage.getItem('commandcore:pending-permission-reauthorize');sessionStorage.removeItem('commandcore:pending-permission-reauthorize');}catch{}
  if(!raw)return;
  try{
    const intent=JSON.parse(raw),i=this.devices().findIndex(d=>d.id===intent.deviceId);
    if(i<0||intent.subject!==this.session()?.subject||intent.expiresAt<Date.now()||!['FULL_CONTROL','STANDARD','READ_ONLY'].includes(intent.level))return;
    this.selected.set(i);this.view.set('access');this.onAccess();this.mobileFocusWorkspace();
    this.permissionChoice=intent.level;
    if(this.permissionOAuthReady(intent.level)&&(intent.level!=='FULL_CONTROL'||this.localFullReady())){
      this.message(this.levelName(intent.level)+' OAuth authorization is ready. Review and confirm the change for '+this.selectedDevice()?.display_name+'.');
    } else if(!this.permissionOAuthReady(intent.level)){
      this.permissionError.set('Your OAuth session still lacks '+(intent.level==='FULL_CONTROL'?'commandcore:full':'commandcore:standard')+'. This scope must be granted by the authorization server before changing device permissions.');
    }else{
      this.permissionError.set('Local Full Control is no longer available. Refresh device status and check the privileged helper.');
    }
  }catch{}
 }
 async applyPermission(){
  const d=this.selectedDevice(),pending=this.pendingPermission;
  if(!d||!d.managed_by_me||!pending||d.id!==pending.deviceId||this.permissionBusy())return;
  if(!this.permissionOAuthReady(pending.level)){this.overlay.set('permission-reauthorize');return;}
  this.permissionBusy.set(true);this.permissionError.set('');
  const level=pending.level;
  try{
   await request('/api/managed-devices/'+encodeURIComponent(pending.deviceId)+'/my-permission','PUT',{profile:level,expected_profile:pending.expected_profile,expected_grant:pending.expected_grant});
   this.overlay.set('none');await this.refresh();this.message('Server policy and your grant set to '+this.levelName(level)+'.');
  }catch(e){this.overlay.set('none');this.permissionError.set(this.err(e));await this.refresh();this.message('Permission not changed: '+this.err(e));}
  finally{this.pendingPermission=null;this.permissionBusy.set(false);}
 }
 levelName(level:string|null|undefined){return ({FULL_CONTROL:'Full Control',STANDARD:'Standard',READ_ONLY:'Read Only',NOT_APPLICABLE:'Not applicable',NOT_GRANTED:'Not granted',NO_ACCESS:'No access',UNKNOWN:'Unknown'} as Record<string,string>)[level||'']||level||'Not reported';}
 beginRestoreMyGrant(){const d=this.selectedDevice();if(!d?.managed_by_me||!this.myGrantNeedsRestore())return;this.overlay.set('restore-confirm');}
 async restoreMyGrant(){const d=this.selectedDevice();const subject=this.session()?.subject;
  if(!d?.managed_by_me||!subject||this.permissionBusy())return;
  const level=d.permission_profile==='READ_ONLY'||this.localCeiling()==='READ_ONLY'?'READ_ONLY':'STANDARD';
  this.permissionBusy.set(true);
  try{await request('/api/managed-devices/'+encodeURIComponent(d.id)+'/grants','PUT',{subject,profile:level});this.overlay.set('none');await this.refresh();this.message('Your grant restored without re-enrolling the device.');}
  catch(e){this.message('Restore failed: '+this.err(e));}finally{this.permissionBusy.set(false);}
 }
 beginGrant(){const d=this.selectedDevice();if(!d?.managed_by_me||!this.grantSubject.trim())return;
  if(!['READ_ONLY','STANDARD'].includes(this.grantLevel)){this.message('Account grant API supports Read Only or Standard. Use the device permission control for your own Full Control.');return;}
  this.awaitingGrantRemoval=false;this.overlay.set('grant-confirm');
 }
 beginRemoveGrant(subject:string){if(!this.selectedDevice()?.managed_by_me)return;this.confirmName='';this.grantToRemove=subject;this.awaitingGrantRemoval=true;this.overlay.set('grant-confirm');}
 async applyGrant(){
  const d=this.selectedDevice();if(!d||this.permissionBusy())return;
  this.permissionBusy.set(true);
  try{
   if(this.awaitingGrantRemoval)await request('/api/managed-devices/'+encodeURIComponent(d.id)+'/grants?subject='+encodeURIComponent(this.grantToRemove),'DELETE');
   else await request('/api/managed-devices/'+encodeURIComponent(d.id)+'/grants','PUT',{subject:this.grantSubject.trim(),profile:this.grantLevel});
   this.overlay.set('none');this.grantSubject='';await this.refresh();
   this.message(this.awaitingGrantRemoval?'Account grant removed.':'Account grant saved.');
  }catch(e){this.message('Grant update failed: '+this.err(e));}
  finally{this.permissionBusy.set(false);}
 }
 async loadAudit(){const sessionVersion=this.sessionEpoch.snapshot();const d=this.selectedDevice();if(!d?.managed_by_me||!this.sessionEpoch.isCurrent(sessionVersion))return;this.auditBusy.set(true);this.overlay.set('audit');
  try{const result=await request<any>('/api/managed-devices/'+encodeURIComponent(d.id)+'/audit');if(this.sessionEpoch.isCurrent(sessionVersion)&&this.selectedDevice()?.id===d.id)this.audit.set(result.events||[]);}
  catch(e){if(this.sessionEpoch.isCurrent(sessionVersion)){this.audit.set([]);this.message('Audit unavailable: '+this.err(e));}}finally{if(this.sessionEpoch.isCurrent(sessionVersion))this.auditBusy.set(false);}
 }
 async reloadDeviceDetail(){const sessionVersion=this.sessionEpoch.snapshot();const d=this.selectedDevice();if(!d||!this.sessionEpoch.isCurrent(sessionVersion))return;try{const result=await request<{device:Device}>('/api/devices/'+encodeURIComponent(d.id));if(this.sessionEpoch.isCurrent(sessionVersion)&&this.selectedDevice()?.id===d.id)this.detail.set(result.device);}catch(e){if(this.sessionEpoch.isCurrent(sessionVersion))this.message(this.err(e));}}
 onAccess(){this.permissionChoice=this.ownGrant()||'STANDARD';this.renameValue=this.selectedDevice()?.display_name||'';void this.reloadDeviceDetail();}
 confirmDanger(task:()=>Promise<void>){this.confirmation=task;this.confirmName='';this.overlay.set('confirm');}
 async confirmAction(){if(this.confirmName!==this.selectedDevice()?.display_name)return;try{await this.confirmation?.();this.overlay.set('none');}catch(e){this.message(this.err(e));}}
 async revokeDevice(){const d=this.selectedDevice();if(!d)return;try{await request('/api/managed-devices/'+encodeURIComponent(d.id)+'/revoke','POST');this.message('Device revoked.');await this.refresh();}catch(e){this.message(this.err(e));throw e;}}
 async renameDevice(name:string){const d=this.selectedDevice();if(!d||!name.trim())return;try{await request('/api/managed-devices/'+encodeURIComponent(d.id),'PATCH',{display_name:name.trim()});this.message('Name updated');await this.refresh();this.renameValue=name.trim();}catch(e){this.message(this.err(e));}}
 runPalette(term:string){const q=term.toLowerCase();this.overlay.set('none');if(q.includes('browser'))void this.show('browser');else if(q.includes('activity'))void this.show('activity');else if(q.includes('hardware'))void this.show('hardware');else if(q.includes('access'))void this.show('access');else if(q.includes('device')||q.includes('add'))this.openAdd();else if(q.includes('file'))void this.show('files');else void this.show('workspace');}
 message(value:string){this.notice.set(value);setTimeout(()=>{if(this.notice()===value)this.notice.set('');},6500);}
 err(e:unknown){return e instanceof Error?e.message:String(e);}
 pct(n:any){return Number.isFinite(+n)?Math.max(0,Math.min(100,+n)):0;}
 fmtBytes(value:any){const n=Number(value);if(!Number.isFinite(n))return '—';return n>=1e12?(n/1e12).toFixed(1)+' TB':n>=1e9?(n/1e9).toFixed(1)+' GB':(n/1e6).toFixed(0)+' MB';}
 fmtTime(value:any){if(!value)return '—';const date=new Date(typeof value==='number'?value*1000:value);return Number.isNaN(+date)?'—':date.toLocaleString();}
 dataItem(row:any){return typeof row==='object'?row.tool||row.operation||row.action||row.event||row.status||'Operation':String(row);}
 dataDetail(row:any){return typeof row==='object'?row.summary||row.args_summary||row.result_summary||row.device_name||row.status||'': '';}
 json(row:any){return JSON.stringify(row,null,2);}
 relative(i:number,n:number){return (i-this.selected()+n)%n;}
}
