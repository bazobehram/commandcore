const $=id=>document.getElementById(id);
const state={devices:[],pending:[],session:null};
const rank={READ_ONLY:0,STANDARD:1,FULL_CONTROL:2};
const esc=value=>String(value??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const time=value=>value?new Date(typeof value==='number'?value*1000:value).toLocaleString():'Never';
// Display the same four permission layers together; authorization remains server-side.
function permissionSummary(device){
    const session=state.session||{};
    const scopes=Array.isArray(session.scopes)?session.scopes:[];
    const bypass=['panel-cookie','bootstrap-bearer'].includes(session.auth_kind);
    const oauth=bypass?'FULL_CONTROL':!state.session||!Array.isArray(session.scopes)?undefined:scopes.includes('commandcore:full')?'FULL_CONTROL':scopes.includes('commandcore:standard')?'STANDARD':scopes.includes('commandcore:read')?'READ_ONLY':'No access';
    const grant=device.access_max_permission_profile??(device.is_owner?'FULL_CONTROL':undefined);
    const caps=device.capabilities||{};
    const local=caps.local_max_permission_profile??'STANDARD';
    const localNote=caps.local_max_permission_profile==null?'Not reported; server default is STANDARD.':[
        'Reported local maximum: '+local+'.',
        caps.configured_max_permission_profile?'Configured local policy: '+caps.configured_max_permission_profile+'.':'Configured local policy not reported.',
        caps.privileged_helper===true?'Privileged helper available.':caps.privileged_helper===false?'Privileged helper unavailable; FULL_CONTROL requires a healthy helper.':'Privileged helper availability not reported.',
        caps.policy_error?'Local policy error: '+caps.policy_error+'.':''
    ].filter(Boolean).join(' ');
    const layers=[
        {label:'OAuth',profile:oauth,display:bypass?'Not applicable':oauth,note:bypass?'Scope layer does not apply to this recovery/admin session.':oauth==null?'Execution scopes not reported.':oauth==='STANDARD'?'commandcore:standard is present; commandcore:full is absent.':oauth==='FULL_CONTROL'?'commandcore:full is present.':oauth==='READ_ONLY'?'commandcore:read is present; commandcore:standard and commandcore:full are absent.':'No execution scope (commandcore:read, commandcore:standard or commandcore:full). commandcore:admin alone does not grant execution access.'},
        {label:'Server permission',profile:device.permission_profile,note:'Configured device access policy: '+(device.permission_profile??'Not reported')+'.'},
        {label:'Account grant',profile:grant,note:device.is_owner?'Owner access.':grant==null?'Account-to-device maximum not reported.':'Account-to-device maximum: '+grant+'.'},
        {label:'Local ceiling',profile:local,note:localNote+' Cannot be raised remotely.'}
    ];
    const blocked=layers.filter(l=>l.profile==='No access');
    const unknown=layers.filter(l=>l.profile!=='No access'&&!Object.hasOwn(rank,l.profile));
    const profile=blocked.length?'No access':unknown.length?'Unknown':Object.keys(rank).find(p=>rank[p]===Math.min(...layers.map(l=>rank[l.profile])));
    const limiting=blocked.length?blocked:unknown.length||profile==='FULL_CONTROL'?[]:layers.filter(l=>l.profile===profile);
    const reason=blocked.length?'No access: '+limiting.map(l=>l.label).join(', ')+'.':unknown.length?'Permission missing or unrecognized for: '+unknown.map(l=>l.label).join(', ')+'.':limiting.length?'Limited to '+profile+' by '+limiting.map(l=>l.label+' ('+l.profile+')').join(', ')+'.':'All permission layers allow Full Control.';
    return {profile,layers,limiting,reason};
}
function displayPermissionName(v){return ({FULL_CONTROL:'Full Control',READ_ONLY:'Read Only',STANDARD:'Standard'})[v]||v;}
function permissionDisplay(device,expanded=false){
    const summary=permissionSummary(device);
    const oauthLimited=summary.limiting.some(layer=>layer.label==='OAuth');
    const action=oauthLimited?'<a class="button permission-reconnect" href="/auth/login">Reconnect to update OAuth permissions</a>':'';
    const details=expanded?`<p class="muted">Effective permission is the lowest applicable access layer.</p><dl class="permission-layers">${summary.layers.map(layer=>`<dt>${esc(layer.label)}</dt><dd class="${summary.limiting.includes(layer)?'permission-limiter':''}">${esc(displayPermissionName(layer.display??layer.profile??'Not reported'))}${summary.limiting.includes(layer)?' · limiting':''}<div class="muted">${esc(String(layer.note).replaceAll('FULL_CONTROL','Full Control').replaceAll('READ_ONLY','Read Only').replaceAll('STANDARD','Standard'))}</div></dd>`).join('')}</dl>`:'';
    return `<div class="permission-summary"><div class="permission-effective">Effective permission: <strong>${esc(displayPermissionName(summary.profile))}</strong><p class="permission-reason">${esc(summary.reason.replaceAll('FULL_CONTROL','Full Control').replaceAll('READ_ONLY','Read Only').replaceAll('STANDARD','Standard'))}</p>${action}</div>${details}</div>`;
}
// Compare only well-formed release versions, including SemVer prereleases.
function releaseVersion(value){
    if(typeof value!=='string')return null;
    const match=/^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.exec(value);
    if(!match)return null;
    const pre=match[4]?.split('.')||[];
    if(pre.some(p=>/^\d+$/.test(p)&&p.length>1&&p[0]==='0'))return null;
    return {core:match.slice(1,4).map(BigInt),pre};
}
function compareVersions(a,b){
    for(let i=0;i<3;i++)if(a.core[i]!==b.core[i])return a.core[i]>b.core[i]?1:-1;
    if(!a.pre.length||!b.pre.length)return a.pre.length===b.pre.length?0:a.pre.length?-1:1;
    for(let i=0;i<Math.max(a.pre.length,b.pre.length);i++){
        const x=a.pre[i],y=b.pre[i];
        if(x===undefined||y===undefined)return x===undefined?-1:1;
        if(x===y)continue;
        const xn=/^\d+$/.test(x),yn=/^\d+$/.test(y);
        return xn&&yn?(BigInt(x)>BigInt(y)?1:-1):xn!==yn?(xn?-1:1):x>y?1:-1;
    }
    return 0;
}
function updateStatus(device){
    const candidate=device.capabilities?.update_candidate_version;
    const current=releaseVersion(device.agent_version),next=releaseVersion(candidate);
    if(current&&next)return compareVersions(next,current)>0?'Update available: '+candidate+' (reported candidate)':'No newer reported candidate ('+candidate+')';
    return candidate||device.agent_update_available||device.capabilities?.agent_update_status?'Unknown':'Not reported';
}
async function api(path,method='GET',body){const response=await fetch(path,{method,credentials:'same-origin',headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined});const data=await response.json().catch(()=>({}));if(response.status===401){$('login').hidden=false;$('dashboard').hidden=true;throw Error('Sign in to continue.')}if(!response.ok)throw Error(data.detail||'Request failed');return data}
function error(e){$('message').textContent=e.message}
function makeCard(device){
    const node=document.createElement('article');
    node.className='card device-card permission-'+String(permissionSummary(device).profile||'unknown').toLowerCase().replaceAll('_','-').replaceAll(' ','-');
    const platform=String(device.platform||'').toLowerCase();
    const isServer=/(server|home)/i.test((device.display_name||'')+' '+(device.hostname||''));
    const icon=isServer
        ? '<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="4" y="3" width="16" height="8" rx="2"/><rect x="4" y="13" width="16" height="8" rx="2"/><path d="M8 7h.01M8 17h.01M12 7h4M12 17h4"/></svg>'
        : '<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="4" y="4" width="16" height="13" rx="2"/><path d="M2 20h20M9 20l1-3m5 0 1 3"/></svg>';
    node.innerHTML=`<div class="device-head"><span class="device-icon" aria-hidden="true">${icon}</span><div class="device-ident"><h2>${esc(device.display_name)}</h2><div class="muted">${esc(device.hostname)}</div><p class="device-platform">${esc(device.platform)} · ${esc(device.architecture)}</p></div></div><span class="status ${device.connected?'online':'offline'}">● ${device.revoked_at?'Revoked':device.connected?'Online':'Offline'}</span>${permissionDisplay(device)}<div class="device-footer"><div class="device-meta"><div class="meta-row"><span>Agent</span><strong>${esc(device.capabilities?.agent_implementation||'Agent')} ${esc(device.agent_version)}</strong></div><div class="meta-row"><span>Last seen</span><strong>${esc(time(device.last_seen))}</strong></div><div class="meta-row"><span>Update</span><strong>${esc(updateStatus(device))}</strong></div></div></div>`;
    const permissionControl=node.querySelector('.permission-effective');
    permissionControl.setAttribute('role','button');
    permissionControl.setAttribute('tabindex','0');
    permissionControl.setAttribute('aria-label','View '+device.display_name+' details and '+displayPermissionName(permissionSummary(device).profile)+' permissions');
    permissionControl.title='View device details';
    permissionControl.addEventListener('click',event=>{if(!event.target.closest('a,button'))detail(device)});
    permissionControl.addEventListener('keydown',event=>{
        if(event.target===permissionControl&&(event.key==='Enter'||event.key===' ')){
            event.preventDefault();detail(state.devices.find(item=>String(item.id)===String(device.id))||device);
        }
    });
    const button=document.createElement('button');
    button.className='view-device';
    button.textContent='View device  ›';
    button.onclick=()=>detail(state.devices.find(item=>String(item.id)===String(device.id))||device);
    node.querySelector('.device-footer').append(button);
    return node;
}
function reconcileDeviceCards(devices){
    const grid=$('devices');
    const oldNodes=new Map([...grid.querySelectorAll('.device-card[data-device-id]')].map(n=>[n.dataset.deviceId,n]));
    const visible=devices.filter(d=>!d.revoked_at);
    const next=visible.map(device=>{
        const id=String(device.id);
        const signature=JSON.stringify([
            device.display_name,device.hostname,device.platform,device.architecture,
            device.connected,device.permission_profile,device.access_max_permission_profile,
            device.is_owner,device.agent_version,device.capabilities?.agent_implementation,
            device.capabilities?.local_max_permission_profile,
            device.capabilities?.configured_max_permission_profile,
            device.capabilities?.privileged_helper,device.capabilities?.policy_error,
            updateStatus(device),state.session?.scopes
        ]);
        let node=oldNodes.get(id);
        if(!node||node.dataset.signature!==signature){
            node=makeCard(device);node.dataset.deviceId=id;node.dataset.signature=signature;
        }else{
            const lastSeen=node.querySelector('.meta-row:nth-child(2) strong');
            if(lastSeen)lastSeen.textContent=time(device.last_seen);
        }
        return node;
    });
    if(!visible.length){
        if(!grid.querySelector('.empty'))grid.innerHTML='<div class="empty">No devices granted yet. Add a device to get started.</div>';
    }else if(next.length!==grid.children.length||next.some((n,i)=>grid.children[i]!==n)){
        grid.replaceChildren(...next);
    }
}
let refreshPromise=null,pendingSignature=null;
async function refresh(){if(refreshPromise)return refreshPromise;refreshPromise=(async()=>{try{const [devices,managed,pending]=await Promise.all([api('/api/devices'),api('/api/managed-devices'),api('/api/enrollment/pending')]);const merged=new Map(devices.devices.map(d=>[d.id,d]));for(const device of managed.devices){const access=merged.get(device.id)||{};merged.set(device.id,{...device,...access,managed_by_me:true,grants:device.grants})}state.devices=[...merged.values()];state.pending=pending.enrollments;reconcileDeviceCards(state.devices);$('summary').textContent=`${state.devices.filter(d=>!d.revoked_at).length} devices · ${state.devices.filter(d=>d.connected&&!d.revoked_at).length} online`;$('pendingCount').textContent=state.pending.length;const nextPendingSignature=JSON.stringify(state.pending);if(nextPendingSignature!==pendingSignature){const previousInputs=new Map([...$('pending').querySelectorAll('article[data-enrollment-id]')].map(n=>[n.dataset.enrollmentId,{code:n.querySelector('input[name=code]')?.value||'',grant:!!n.querySelector('input[name=grant]')?.checked}]));$('pending').replaceChildren();for(const p of state.pending){const node=document.createElement('article');node.className='card';node.dataset.enrollmentId=String(p.id);node.innerHTML=`<h2>${esc(p.metadata.display_name)}</h2><p>${esc(p.metadata.hostname)} · ${esc(p.metadata.platform)} · ${esc(p.metadata.architecture)}</p><span class="badge">${esc(p.metadata.local_ceiling)}</span><p class="mono">Code: ${esc(p.verification_code)}</p><p class="muted">Created: ${esc(time(p.created_at))}<br>Expires: ${esc(time(p.expires_at))}</p>`;const form=document.createElement('form');form.innerHTML='<label>Enter the code shown on the Agent<input name="code" required minlength="9" maxlength="9" autocomplete="off"></label><label><input name="grant" type="checkbox"> Grant this device to my account</label><button name="approve" value="true">Approve</button><button name="approve" value="false" class="danger">Reject</button>';const old=previousInputs.get(String(p.id));if(old){form.elements.code.value=old.code;form.elements.grant.checked=old.grant;}form.onsubmit=e=>{e.preventDefault();action('/api/enrollment/pending/'+encodeURIComponent(p.id)+'/decision','POST',{code:form.elements.code.value.toUpperCase(),approve:e.submitter?.value==='true',grant_to_me:form.elements.grant.checked})};node.append(form);$('pending').append(node)}pendingSignature=nextPendingSignature;}const live=$('enrollmentLive');if(live)live.textContent=state.pending.length?state.pending.length+' enrollment request(s) waiting for review.':'Waiting for enrollment — requests appear here automatically.';const connected=$('onboardOnline');if(connected)connected.textContent=connectionSummary();if($('detail').open&&detailDeviceId){const current=state.devices.find(item=>String(item.id)===detailDeviceId);if(current){const badge=$('detailLiveStatus');if(badge){badge.className='inline-status '+(current.connected?'online':'offline');badge.textContent=current.connected?'● Online':'● Offline';}const seen=$('detailLastSeen');if(seen)seen.textContent=time(current.last_seen);}}if(!state.pending.length&&!$('pending').querySelector('.empty'))$('pending').innerHTML='<div class="empty">No pending enrollments reviewed by your account. Open the new machine’s enrollment link to review it.</div>';$('message').textContent=''}catch(e){error(e)}})();try{return await refreshPromise}finally{refreshPromise=null}}
function row(label,value){return `<dt>${esc(label)}</dt><dd>${esc(value)}</dd>`}
let detailDeviceId=null;
function detail(d){
    detailDeviceId=String(d.id);
    $('detailTitle').textContent=d.display_name;
    const caps=d.capabilities||{},summary=permissionSummary(d);
    const readable=value=>String(value||'').replaceAll('FULL_CONTROL','Full Control').replaceAll('READ_ONLY','Read Only').replaceAll('STANDARD','Standard');
    const available=['filesystem','shell','process','git','docker','services','packages','system_power','browser','desktop','screen','keyboard','mouse','clipboard','agent_update','privileged_helper'];
    $('detailBody').innerHTML=
      '<div class="detail-overview"><div class="detail-hero-top"><span id="detailLiveStatus" class="inline-status '+(d.connected?'online':'offline')+'">'+(d.connected?'● Online':'● Offline')+'</span><span class="detail-platform">'+esc(d.platform)+' · '+esc(d.architecture)+'</span></div>'+
      '<div class="detail-access-head"><span>Effective permission</span><strong class="detail-access-name">'+esc(displayPermissionName(summary.profile))+'</strong><p>'+esc(readable(summary.reason))+'</p></div></div>'+
      '<div class="detail-quick-stats"><div><span>Agent</span><strong>'+esc(caps.agent_implementation||'Agent')+' '+esc(d.agent_version)+'</strong></div><div><span>Last seen</span><strong id="detailLastSeen">'+esc(time(d.last_seen))+'</strong></div><div><span>Update</span><strong>'+esc(updateStatus(d))+'</strong></div></div>'+
      '<details class="detail-disclosure" id="cc-permissions"><summary>Permission breakdown <span>OAuth, server, account, device</span></summary><div class="permission-lines">'+summary.layers.map(layer=>'<div class="permission-line"><span>'+esc(layer.label)+'</span><strong>'+esc(displayPermissionName(layer.display??layer.profile??'Unknown'))+'</strong></div>').join('')+'</div><p class="muted">The lowest access layer determines effective permission. Local policy cannot be raised remotely.</p></details>'+
      '<details class="detail-disclosure" id="cc-device-info"><summary>Agent and device information <span>Version, identity, connection</span></summary><dl class="detail-data">'+row('Device ID',d.id)+row('Hostname',d.hostname)+row('OS / architecture',d.platform+' / '+d.architecture)+row('Agent / protocol',d.agent_version+' / '+d.agent_protocol_version)+row('Key generation',d.key_generation)+row('Approved',time(d.approved_at))+row('Last seen',time(d.last_seen))+row('Update status',updateStatus(d))+'</dl></details>'+
      '<details class="detail-disclosure" id="cc-capabilities"><summary>Capabilities <span>'+available.filter(c=>caps[c]===true).length+' available</span></summary><div class="capabilities">'+available.map(c=>'<span class="cap '+(caps[c]===true?'available':'')+'">'+esc(c.replaceAll('_',' '))+': '+(caps[c]===true?'available':'unavailable')+'</span>').join('')+'</div></details>';
    if(d.managed_by_me){const section=document.createElement('section');section.className='section';section.innerHTML='<h3>Device access</h3><p class="muted">Only listed accounts can operate this device. Grants remain bounded by OAuth scopes, server permission and the local ceiling.</p>';for(const grant of d.grants||[]){const line=document.createElement('div');line.className='grant';const text=document.createElement('span');text.className='mono';text.textContent=grant.subject+' · '+grant.max_permission_profile;const remove=document.createElement('button');remove.textContent='Remove grant';remove.onclick=()=>action('/api/managed-devices/'+d.id+'/grants?subject='+encodeURIComponent(grant.subject),'DELETE');line.append(text,remove);section.append(line)}const form=document.createElement('form');form.innerHTML='<label>Account subject<input name="subject" required maxlength="255"></label><label>Grant<select name="profile"><option>READ_ONLY</option><option>STANDARD</option></select></label><button>Save explicit grant</button>';form.onsubmit=e=>{e.preventDefault();action('/api/managed-devices/'+d.id+'/grants','PUT',Object.fromEntries(new FormData(form)))};section.append(form);const rename=document.createElement('form');rename.innerHTML=`<label>Display name<input name="display_name" required maxlength="120" value="${esc(d.display_name)}"></label><button>Rename device</button>`;rename.onsubmit=e=>{e.preventDefault();action('/api/managed-devices/'+d.id,'PATCH',Object.fromEntries(new FormData(rename)))};section.append(rename);const revoke=document.createElement('button');revoke.textContent='Revoke device';revoke.className='danger';revoke.onclick=()=>{
    revoke.disabled=true;
    const confirmation=document.createElement('section');
    confirmation.className='section';
    confirmation.setAttribute('aria-label','Confirm device revocation');
    const explanation=document.createElement('p');
    explanation.textContent='Revoke '+d.display_name+'? Its Agent will disconnect and its identity will no longer be accepted. Enroll it again to reconnect.';
    const cancel=document.createElement('button');
    cancel.textContent='Keep device';
    cancel.onclick=()=>{confirmation.remove();revoke.disabled=false;revoke.focus()};
    const confirmButton=document.createElement('button');
    confirmButton.textContent='Confirm revocation';
    confirmButton.className='danger';
    confirmButton.onclick=()=>action('/api/managed-devices/'+d.id+'/revoke','POST');
    confirmation.append(explanation,cancel,confirmButton);
    section.append(confirmation);
    cancel.focus();
};section.append(revoke);
const permissionForm=document.createElement('form');
permissionForm.className='device-permission-form';
permissionForm.innerHTML='<h3>Device access policy</h3><label>Server permission<select name="profile"><option value="READ_ONLY">Read Only</option><option value="STANDARD">Standard</option><option value="FULL_CONTROL">Full Control</option></select></label><button type="submit">Update device permission</button>';
permissionForm.elements.profile.value=d.permission_profile;
permissionForm.onsubmit=async e=>{
    e.preventDefault();
    const next=permissionForm.elements.profile.value;
    if(next===d.permission_profile)return;
    if(!window.confirm('Change server permission for '+d.display_name+' to '+displayPermissionName(next)+'?'))return;
    try{
        await api('/api/managed-devices/'+encodeURIComponent(d.id)+'/permissions','POST',{profile:next});
        $('detail').close();await refresh();
    }catch(err){error(err)}
};
section.prepend(permissionForm);
const disclosure=document.createElement('details');
disclosure.className='detail-disclosure';disclosure.id='cc-device-management';
const title=document.createElement('summary');title.textContent='Manage device and access';
disclosure.append(title,section);
addDeviceDiagnostics(section,d);
$('detailBody').append(disclosure)}startLiveActivity(d);$('detail').showModal();$('detail').scrollTop=0}
function addDeviceDiagnostics(section,device){
    const audit=document.createElement('button');
    audit.textContent='View audit';
    const history=document.createElement('section');
    history.className='section';
    history.hidden=true;
    audit.onclick=async()=>{
        audit.disabled=true;
        try{
            const data=await api('/api/managed-devices/'+device.id+'/audit');
            history.replaceChildren();
            const heading=document.createElement('h3');
            heading.textContent='Recent device audit';
            history.append(heading);
            for(const event of data.events){
                const line=document.createElement('p');
                line.textContent=time(event.timestamp)+' · '+event.tool+' · '+event.status+' · '+event.duration_ms+' ms';
                history.append(line);
            }
            if(!data.events.length){const empty=document.createElement('p');empty.textContent='No audit events recorded yet.';history.append(empty)}
            history.hidden=false;
        }catch(e){error(e)}finally{audit.disabled=false}
    };
    const rotate=document.createElement('button');
    rotate.textContent='Rotate key locally';
    rotate.onclick=()=>{
        const instructions=document.createElement('section');
        instructions.className='section';
        const explanation=document.createElement('p');
        explanation.textContent='Run this command on '+device.display_name+' as the Agent account, then restart its Agent service. The private key stays on the device. This action changes no permission or grant.';
        const command=document.createElement('pre');
        command.textContent='commandcore-agent rotate-key';
        instructions.append(explanation,command);
        section.append(instructions);
        rotate.disabled=true;
    };
    section.append(audit,rotate,history);
}
async function action(path,method,body){try{await api(path,method,body);$('detail').close();await refresh()}catch(e){error(e)}}
$('close').onclick=()=>{$('detail').close();detailDeviceId=null};$('refresh').onclick=refresh;
// The four Control Plane sections are owner-scoped and explicitly selected.
let activePanel='devices',browserLivePaused=false,browserCursor=-1,activeBrowserClient='',browserViewGeneration=0,browserListGeneration=0;
function showPanel(name,recordHistory=true){
    if(!['devices','pending','activity','browser'].includes(name))name='devices';
    if(recordHistory&&location.hash!=='#'+name)history.pushState({panel:name},'','#'+name);
    activePanel=name;
    if(name!=='browser')browserViewGeneration++;
    document.querySelector('.footnote').hidden=name!=='devices';
    $('panelTitle').textContent=({devices:'Devices',pending:'Pending enrollments',activity:'Activity',browser:'Browser'})[name]||'Devices';
    $('summary').hidden=name!=='devices';
    $('add').hidden=name!=='devices';
    for(const id of ['devices','pending','activity','browser']){
        $(id).hidden=(id!==name);
        $(id+'Tab').classList.toggle('selected',id===name);
        $(id+'Tab').setAttribute('aria-pressed',String(id===name));
    }
    if(name==='activity')loadActivity();
    if(name==='browser')loadBrowserSessions();
}
$('devicesTab').onclick=()=>showPanel('devices');
$('pendingTab').onclick=()=>showPanel('pending');
$('activityTab').onclick=()=>showPanel('activity');
$('browserTab').onclick=()=>showPanel('browser');
addEventListener('popstate',()=>showPanel(location.hash.slice(1),false));
addEventListener('hashchange',()=>showPanel(location.hash.slice(1),false));
let activityRefresh=null;
async function loadActivity(){
    const target=$('activity');
    const selectedDevice=target.querySelector('#activityDevice')?.value;
    target.replaceChildren();
    target.classList.add('activity-workspace');
    const title=document.createElement('h2');title.textContent='Activity';
    const hint=document.createElement('p');hint.textContent='Owner-authorized operations with results and audit details.';
    const toolbar=document.createElement('div');toolbar.className='activity-toolbar';
    const picker=document.createElement('select');picker.id='activityDevice';picker.setAttribute('aria-label','Select activity device');
    const search=document.createElement('input');search.type='search';search.placeholder='Search operations';search.setAttribute('aria-label','Search operations');
    const status=document.createElement('select');status.setAttribute('aria-label','Filter operation status');
    for(const [value,label] of [['all','All statuses'],['ok','Successful'],['error','Errors'],['running','Running']]){
      const option=document.createElement('option');option.value=value;option.textContent=label;status.append(option);
    }
    for(const d of state.devices.filter(d=>!d.revoked_at)){
        const option=document.createElement('option');option.value=d.id;option.textContent=d.display_name;picker.append(option);
    }
    if([...picker.options].some(o=>o.value===selectedDevice))picker.value=selectedDevice;
    toolbar.append(picker,search,status);
    const results=document.createElement('div');results.className='activity-results';
    target.append(title,hint,toolbar,results);
    let lastFingerprint=null,lastEvents=[],generation=0;
    function render(){
      const term=search.value.toLowerCase().trim(),filter=status.value;
      const filtered=lastEvents.filter(e=>{
        const outcome=String(e.status||'unknown').toLowerCase();
        const isError=['error','failed','failure','denied'].includes(outcome);
        const isRunning=['running','pending','started','in_progress'].includes(outcome);
        if(filter==='ok'&&!['ok','completed','success'].includes(outcome))return false;
        if(filter==='error'&&!isError)return false;
        if(filter==='running'&&!isRunning)return false;
        return !term||[e.tool,e.status,e.operation_id,e.device].some(v=>String(v||'').toLowerCase().includes(term));
      });
      results.replaceChildren();
      if(!filtered.length){results.textContent=lastEvents.length?'No matching operations.':'No recent operations.';return}
      for(const event of filtered.slice(0,60)){
        const entry=document.createElement('details');entry.className='activity-entry';
        entry.dataset.status=String(event.status||'unknown').toLowerCase();
        const summary=document.createElement('summary');
        summary.textContent=String(event.tool||'Operation')+' · '+String(event.status||'unknown')+(event.duration_ms==null?'':' · '+event.duration_ms+' ms');
        const detail=document.createElement('pre');
        // Audit details are escaped; event values are never interpreted as markup.
        detail.textContent=JSON.stringify(event,null,2);
        entry.append(summary,detail);results.append(entry);
      }
    }
    const update=async()=>{
      if(!picker.value){results.textContent='No accessible devices.';return}
      const requestedDevice=picker.value,requestGeneration=++generation;
      if(lastFingerprint===null)results.textContent='Loading activity…';
      try{
        const data=await api('/api/devices/'+encodeURIComponent(requestedDevice)+'/activity');
        if(activePanel!=='activity'||requestGeneration!==generation||picker.value!==requestedDevice)return;
        const events=Array.isArray(data.events)?data.events:[];
        const fingerprint=JSON.stringify(events);
        if(fingerprint===lastFingerprint)return;
        lastFingerprint=fingerprint;lastEvents=events;render();
      }catch(e){
        if(requestGeneration===generation&&picker.value===requestedDevice)
          results.textContent=String(e.message||'Activity unavailable');
      }
    };
    picker.onchange=()=>{lastFingerprint=null;lastEvents=[];update()};
    search.oninput=render;status.onchange=render;
    activityRefresh=update;await update();
}

function browserUiState(message){
    const status=$('browserStatus');status.textContent=message;
    const lower=String(message).toLowerCase();
    status.dataset.state=lower.includes('unavailable')||lower.includes('error')?'error':lower.includes('paused')||lower.includes('private')?'paused':lower.includes('working')||lower.includes('checking')?'working':'idle';
}
function resetBrowserPreview(){
    $('browserImage').hidden=true;$('browserImage').removeAttribute('src');
    $('browserPage').textContent='';$('browserAction').textContent='';
}
function prepareBrowserPanel(){
    const panel=$('browser');if(panel.dataset.polished)return;panel.dataset.polished='true';
    const heading=panel.querySelector('h2');if(heading){heading.textContent='Live session';heading.classList.add('browser-title');}
    const status=$('browserStatus');status.classList.add('browser-state');
    const picker=$('browserSession');const label=picker.closest('label');label?.classList.add('browser-picker');
    const controls=document.createElement('div');controls.className='browser-controls';
    for(const id of ['browserRefresh','browserPause','browserTakeover'])controls.append($ (id));
    label?.insertAdjacentElement('afterend',controls);
    const toolbar=document.createElement('div');toolbar.className='browser-toolbar';
    toolbar.append(label,controls);
    status.insertAdjacentElement('afterend',toolbar);
    $('browserPage').classList.add('browser-page');
    $('browserAction').classList.add('browser-action');
    $('browserActivity').classList.add('browser-activity-link');
}
prepareBrowserPanel();
async function loadBrowserSessions(){
    const select=$('browserSession');
    const requestGeneration=++browserListGeneration;
    browserUiState('Checking owned Browser sessions…');
    try{
        const data=await api('/api/browser/sessions');
        if(requestGeneration!==browserListGeneration||activePanel!=='browser')return;
        const sessions=Array.isArray(data.sessions)?data.sessions:[];
        const previous=select.value;
        select.replaceChildren();
        for(const row of sessions){
            const option=document.createElement('option');option.value=row.client_id;
            option.textContent='Session '+String(row.session_id||'').slice(0,8);
            select.append(option);
        }
        if(previous&&sessions.some(s=>s.client_id===previous))select.value=previous;
        if(!sessions.length){
            $('browser').classList.add('browser-empty');$('browser').classList.remove('browser-private');
            $('browserPause').disabled=true;select.disabled=true;
            activeBrowserClient='';browserCursor=-1;browserViewGeneration++;
            $('browserTakeover').disabled=true;resetBrowserPreview();
            browserUiState(data.enabled===false?'Browser viewer unavailable.':'No active Browser sessions for this account.');
            return;
        }
        $('browser').classList.remove('browser-empty');
        $('browserPause').disabled=false;select.disabled=false;
        $('browserTakeover').disabled=false;
        if(activeBrowserClient!==select.value){activeBrowserClient=select.value;browserCursor=-1;browserViewGeneration++;resetBrowserPreview();}
        await refreshBrowserFrame();
    }catch(e){
        if(requestGeneration!==browserListGeneration||activePanel!=='browser')return;
        browserViewGeneration++;
        $('browserTakeover').disabled=true;
        $('browserPause').disabled=true;
        resetBrowserPreview();
        browserUiState(String(e.message||'Browser session unavailable'));
    }
}
async function refreshBrowserFrame(){
    if(!activeBrowserClient||browserLivePaused)return;
    const clientId=activeBrowserClient, generation=browserViewGeneration, afterSequence=browserCursor;
    try{
        const data=await api('/api/browser/frame?client_id='+encodeURIComponent(clientId)+'&after_sequence='+afterSequence);
        if(activePanel!=='browser'||browserLivePaused||clientId!==activeBrowserClient||generation!==browserViewGeneration)return;
        const stateLabel=String(data.state||'unknown');
        if(stateLabel==='awaiting_human'){
            $('browser').classList.add('browser-private');$('browserTakeover').disabled=true;
            const link=$('browserAction').querySelector('a[href^="/browser/console/"]');
            resetBrowserPreview();if(link)$('browserAction').replaceChildren(link);
            browserUiState('Private human control active. AI page contents are hidden.');
            return;
        }
        $('browser').classList.remove('browser-private');$('browserTakeover').disabled=false;
        if(data.changed&&typeof data.screenshot_base64==='string'){
            if(!/^[A-Za-z0-9+/=]+$/.test(data.screenshot_base64))throw Error('Invalid image response');
            $('browserImage').src='data:image/png;base64,'+data.screenshot_base64;
            $('browserImage').hidden=false;
            browserCursor=Number.isInteger(data.sequence)?data.sequence:browserCursor;
            $('browserPage').textContent=String(data.title||'')+' · '+String(data.url||'');
        }
        $('browserAction').textContent=String(data.action||'');
        browserUiState(stateLabel==='running'?'Browser is working…':'Live session ready');
    }catch(e){
        if(activePanel!=='browser'||clientId!==activeBrowserClient||generation!==browserViewGeneration)return;
        resetBrowserPreview();
        browserUiState(String(e.message||'Browser frame unavailable'));
    }
}
$('browserSession').onchange=()=>{
    activeBrowserClient=$('browserSession').value;browserCursor=-1;browserViewGeneration++;
    $('browser').classList.remove('browser-private');resetBrowserPreview();refreshBrowserFrame();
};
$('browserRefresh').onclick=()=>{browserLivePaused=false;browserViewGeneration++;$('browserPause').textContent='Pause live view';loadBrowserSessions()};
$('browserPause').onclick=()=>{
    browserLivePaused=!browserLivePaused;
    browserViewGeneration++;
    $('browserPause').textContent=browserLivePaused?'Resume live view':'Pause live view';
    browserUiState(browserLivePaused?'Live viewing paused':'Live viewing resumed');
    if(!browserLivePaused)refreshBrowserFrame();
};
$('browserTakeover').onclick=async()=>{
    if(!activeBrowserClient)return;
    const clientId=activeBrowserClient,generation=++browserViewGeneration;
    $('browserTakeover').disabled=true;
    $('browser').classList.add('browser-private');
    resetBrowserPreview();
    browserUiState('Requesting private control…');
    try{
        const response=await api('/api/browser/handoff','POST',{client_id:clientId});
        if(generation!==browserViewGeneration||clientId!==activeBrowserClient||activePanel!=='browser')return;
        // Only same-origin relative handoff routes returned by the server.
        if(typeof response.handoff_path!=='string'||!/^\/browser\/console\/[A-Za-z0-9_-]+$/.test(response.handoff_path))throw Error('Invalid handoff route');
        const link=document.createElement('a');link.textContent='Open private control';
        link.href=response.handoff_path;link.target='_blank';link.rel='noopener noreferrer';
        $('browserAction').replaceChildren(link);
        browserUiState('Private control ready. Page contents are hidden.');
    }catch(e){
        if(generation!==browserViewGeneration||clientId!==activeBrowserClient)return;
        $('browser').classList.remove('browser-private');
        browserUiState(String(e.message||'Private control unavailable'));
    }finally{
        if(generation===browserViewGeneration&&clientId===activeBrowserClient)
            $('browserTakeover').disabled=$('browser').classList.contains('browser-private');
    }
};
setInterval(()=>{if(activePanel==='browser'&&!browserLivePaused&&!document.hidden)refreshBrowserFrame()},2500);

const linuxCommands=[
    ['install','Install CommandCore','curl -fsSL '+location.origin+'/install/linux | sh'],
    ['status','Check connection status','commandcore-agent status'],
    ['activity','Watch CommandCore activity','commandcore-agent activity'],
    ['follow','Watch live service logs','journalctl --user -u commandcore-agent.service -f'],
    ['service','Check service status','systemctl --user status commandcore-agent.service'],
    ['recent','View recent logs','journalctl --user -u commandcore-agent.service -n 100 --no-pager'],
    ['fallback','If the agent command is not found','~/.local/bin/commandcore-agent activity']
];
function commandBlock(key){
    const command=linuxCommands.find(entry=>entry[0]===key);
    if(!command)return '';
    return '<div class="onboard-command" data-command-key="'+esc(key)+'"><div class="onboard-command-head"><span>'+esc(command[1])+'</span><button type="button" class="copy-command" data-copy-command="'+esc(key)+'" aria-label="Copy '+esc(command[1])+' command">Copy</button></div><pre><code>'+esc(command[2])+'</code></pre></div>';
}
function connectionSummary(){
    const visible=state.devices.filter(item=>!item.revoked_at);
    const online=visible.filter(item=>item.connected);
    return online.length+' of '+visible.length+' authorized device(s) online'+(online.length?': '+online.map(item=>item.display_name).join(', '):'.')+'. Confirm the new hostname appears online before treating connection as verified.';
}
function openAddDevice(){
    detailDeviceId=null;
    $('detailTitle').textContent='Add a device';
    $('detailBody').innerHTML=
       '<div class="onboard-panel">'+
       '<div class="onboard-intro"><strong>Linux setup</strong><p>Install as your regular Linux user. Do not use sudo for this command. Follow progress in the machine’s terminal, then approve its enrollment here.</p></div>'+
       '<section class="onboard-section"><div class="onboard-section-head"><span class="onboard-step">01</span><div><h3>Install CommandCore</h3><p>Run the installer on the new Linux device.</p></div></div>'+
       commandBlock('install')+
       '<p class="onboard-notice"><strong>Deployment notice:</strong> The public installer is not yet verified against all merged Linux fixes. Review terminal output before relying on it. This panel does not assert installation success.</p></section>'+
       '<section class="onboard-section"><div class="onboard-section-head"><span class="onboard-step">02</span><div><h3>Connect your device</h3><p>Enrollment requires explicit verification and account approval.</p></div></div>'+
       '<ol class="onboard-instructions"><li>Wait for the installer to finish and check its terminal result.</li><li>Open the enrollment link printed on the new device and sign in.</li><li>Compare the device details and verification code, then approve the enrollment.</li><li>Verify the device is online in Devices. Approval alone does not prove the agent connected.</li></ol>'+
       '<div id="enrollmentLive" class="onboard-live" aria-live="polite">Checking enrollment requests…</div>'+
       '<div id="onboardOnline" class="onboard-connected" aria-live="polite">Checking connected devices…</div>'+
       '<button type="button" id="reviewEnrollments" class="onboard-secondary">Review pending enrollments</button></section>'+
       '<section class="onboard-section"><div class="onboard-section-head"><span class="onboard-step">03</span><div><h3>Verify installation</h3><p>Check the agent connection and service state after enrollment.</p></div></div>'+commandBlock('status')+commandBlock('service')+'</section>'+
       '<section class="onboard-section onboard-recommended"><div class="onboard-section-head"><span class="onboard-step">04</span><div><h3>Monitor activity</h3><p>Recommended: keep this command running to see CommandCore operations.</p></div></div>'+commandBlock('activity')+'</section>'+
       '<details class="onboard-troubleshooting"><summary>Troubleshooting and existing installations</summary>'+
       '<p>For diagnostics, inspect live or recent service logs. If the CLI is not on PATH, use the absolute command below.</p>'+
       commandBlock('follow')+commandBlock('recent')+commandBlock('fallback')+
       '<div class="onboard-existing"><h3>Already installed?</h3><p>Use the existing agent configuration to reconnect or upgrade. A supported installer should preserve the device identity, but check the installer’s behavior before rerunning it. Never delete <code>~/.config/commandcore/agent.json</code> as routine troubleshooting. Never replace unrelated services.</p>'+
       '<p>Existing verified legacy installations may use a different service or binary path. Inspect those before making changes.</p>'+
       '<p>If enrollment must be restarted, follow your existing agent’s documented procedure; do not reset keys or identity without a recovery plan.</p></div></details>'+
       '<section class="onboard-windows"><h3>Windows</h3><p>Not yet production-ready. This guide covers Linux only.</p></section>'+
       '</div>';
    $('detailBody').querySelectorAll('[data-copy-command]').forEach(button=>{
        button.addEventListener('click',async()=>{
            const cmd=linuxCommands.find(entry=>entry[0]===button.dataset.copyCommand);
            if(!cmd)return;
            try{
                await navigator.clipboard.writeText(cmd[2]);
                button.textContent='Copied';button.dataset.copyState='success';
                setTimeout(()=>{if(button.isConnected){button.textContent='Copy';button.dataset.copyState=''}},1700);
            }catch(e){
                button.textContent='Select to copy';button.dataset.copyState='error';
                const selection=getSelection();const range=document.createRange();
                range.selectNodeContents(button.closest('.onboard-command').querySelector('code'));
                selection?.removeAllRanges();selection?.addRange(range);
            }
        });
    });
    $('reviewEnrollments').onclick=()=>{$('detail').close();showPanel('pending')};
    const live=$('enrollmentLive');
    live.textContent=state.pending.length?state.pending.length+' enrollment request(s) waiting for review.':'Waiting for enrollment — requests appear here automatically.';
    const connected=$('onboardOnline');if(connected)connected.textContent=connectionSummary();
    $('detail').showModal();$('detail').scrollTop=0;
}
$('add').onclick=openAddDevice;
$('signout').onclick=async()=>{try{await api('/api/session','DELETE');location.reload()}catch(e){error(e)}};
$('bootstrap').onsubmit=async e=>{e.preventDefault();try{await api('/api/session','POST',{token:$('token').value});$('token').value='';await init()}catch(e){error(e)}};
// Browsers decide when standalone installation is available. Never force a prompt.
const installAppButton=document.createElement('button');
installAppButton.id='installApp';
installAppButton.type='button';
installAppButton.className='install-app';
installAppButton.textContent='Install app';
installAppButton.hidden=true;
$('signout').before(installAppButton);
let deferredInstallPrompt=null;
addEventListener('beforeinstallprompt',event=>{
    event.preventDefault();
    deferredInstallPrompt=event;
    installAppButton.hidden=false;
});
installAppButton.addEventListener('click',async()=>{
    const prompt=deferredInstallPrompt;
    if(!prompt)return;
    deferredInstallPrompt=null;
    installAppButton.hidden=true;
    try{await prompt.prompt();await prompt.userChoice;}catch(e){/* Browser handles the installation result. */}
});
addEventListener('appinstalled',()=>{deferredInstallPrompt=null;installAppButton.hidden=true;});
async function init(){try{state.session=await api('/api/session');$('account').textContent='Signed in';$('account').title=state.session.subject;$('signout').hidden=false;$('login').hidden=true;$('dashboard').hidden=false;await refresh();
        const nav=document.querySelector('.tabs');
        nav?.setAttribute('role','navigation');nav?.setAttribute('aria-label','Control Plane sections');
        for(const id of ['devices','pending','activity','browser']){
            $(id+'Tab').setAttribute('aria-controls',id);
        }
        showPanel(location.hash.slice(1)||'devices',false);
        $('dashboard').classList.add('cc-enter');
        setTimeout(()=>$('dashboard').classList.remove('cc-enter'),850);
    }catch(e){$('login').hidden=false;const config=await api('/auth/config').catch(()=>({}));$('oauth').hidden=!config.oauth_available;error(e)}}init();setInterval(()=>{if(!document.hidden&&!$('dashboard').hidden)refresh()},2000);document.addEventListener('visibilitychange',()=>{if(!document.hidden&&!$('dashboard').hidden)refresh()});window.addEventListener('focus',()=>{if(!$('dashboard').hidden)refresh()});

let activityTimer;
let activityDevice;
function startLiveActivity(device){
    clearInterval(activityTimer);
    activityDevice=device.id;
    const section=document.createElement('section');
    section.className='section detail-section';section.id='cc-live-activity';
    const heading=document.createElement('h3');heading.textContent='Live Activity';
    const notice=document.createElement('p');notice.className='muted';
    notice.textContent='Recent operations and Agent connection events. Expand an entry for its source, execution ID, outcome and available health signals. Commands, file contents and environment values are omitted.';
    const stream=document.createElement('div');section.append(heading,notice,stream);$('detailBody').append(section);
    async function update(){
        if(activityDevice!==device.id){return}
        try{
            const data=await api('/api/devices/'+encodeURIComponent(device.id)+'/activity');
            if(activityDevice!==device.id){return}
            const opened=new Set([...stream.querySelectorAll('details[open]')].map(n=>n.dataset.execution));
            stream.replaceChildren();
            for(const event of data.events){
                const item=document.createElement('details');item.dataset.execution=event.execution_id;item.open=opened.has(event.execution_id);
                const summary=document.createElement('summary');summary.textContent=event.tool+' · '+event.status+' · '+(event.duration_ms==null?'running':event.duration_ms+' ms')+(event.health_summary?.state==='warning'?' · resource warning':'');
                const details=document.createElement('pre');details.textContent=JSON.stringify(event,null,2);item.append(summary,details);stream.append(item);
            }
            if(!data.events.length){stream.textContent='No dispatched operations recorded yet.'}
        }catch(e){stream.textContent=e.message;clearInterval(activityTimer)}
    }
    update();activityTimer=setInterval(()=>{if($('detail').open&&!document.hidden){update()}else if(!$('detail').open){clearInterval(activityTimer)}},2000);
}

// Check live Browser session list periodically without recreating the page.
setInterval(()=>{if(!document.hidden&&activePanel==='browser')loadBrowserSessions()},6000);

setInterval(()=>{if(!document.hidden&&activePanel==='activity'&&activityRefresh)activityRefresh()},4000);
