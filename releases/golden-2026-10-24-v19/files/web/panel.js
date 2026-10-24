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
        {label:'Server permission',profile:device.permission_profile,note:'Configured server device profile: '+(device.permission_profile??'Not reported')+'.'},
        {label:'Account grant',profile:grant,note:device.is_owner?'Owner access.':grant==null?'Account-to-device maximum not reported.':'Account-to-device maximum: '+grant+'.'},
        {label:'Local ceiling',profile:local,note:localNote+' Cannot be raised remotely.'}
    ];
    const blocked=layers.filter(l=>l.profile==='No access');
    const unknown=layers.filter(l=>l.profile!=='No access'&&!Object.hasOwn(rank,l.profile));
    const profile=blocked.length?'No access':unknown.length?'Unknown':Object.keys(rank).find(p=>rank[p]===Math.min(...layers.map(l=>rank[l.profile])));
    const limiting=blocked.length?blocked:unknown.length||profile==='FULL_CONTROL'?[]:layers.filter(l=>l.profile===profile);
    const reason=blocked.length?'No access: '+limiting.map(l=>l.label).join(', ')+'.':unknown.length?'Permission missing or unrecognized for: '+unknown.map(l=>l.label).join(', ')+'.':limiting.length?'Limited to '+profile+' by '+limiting.map(l=>l.label+' ('+l.profile+')').join(', ')+'.':'All applicable layers allow FULL_CONTROL.';
    return {profile,layers,limiting,reason};
}
function permissionDisplay(device,expanded=false){
    const summary=permissionSummary(device);
    return `<div class="permission-summary"><span class="permission-effective">Effective permission: <strong>${esc(summary.profile)}</strong></span><p class="permission-reason">${esc(summary.reason)}</p>${expanded?'<p class="muted">Effective permission is the lowest of the applicable layers. Each limiting layer must allow a higher profile before effective permission can increase.</p>':''}<dl class="permission-layers">${summary.layers.map(layer=>`<dt>${esc(layer.label)}</dt><dd class="${summary.limiting.includes(layer)?'permission-limiter':''}">${esc(layer.display??layer.profile??'Not reported')}${summary.limiting.includes(layer)?' · limiting':''}${expanded?`<div class="muted">${esc(layer.note)}</div>`:''}</dd>`).join('')}</dl></div>`;
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
function makeCard(device){const node=document.createElement('article');node.className='card';node.innerHTML=`<span class="status ${device.connected?'online':'offline'}">● ${device.revoked_at?'Revoked':device.connected?'Online':'Offline'}</span><h2>${esc(device.display_name)}</h2><div class="muted">${esc(device.hostname)}</div><p>${esc(device.platform)} · ${esc(device.architecture)}</p>${permissionDisplay(device)}<p class="muted">${esc(device.capabilities?.agent_implementation||'Agent')} ${esc(device.agent_version)}<br>Last seen: ${esc(time(device.last_seen))}<br>Update status: ${esc(updateStatus(device))}</p>`;const button=document.createElement('button');button.textContent='View device';button.onclick=()=>detail(device);node.append(button);return node}
async function refresh(){try{const [devices,managed,pending]=await Promise.all([api('/api/devices'),api('/api/managed-devices'),api('/api/enrollment/pending')]);const merged=new Map(devices.devices.map(d=>[d.id,d]));for(const device of managed.devices){const access=merged.get(device.id)||{};merged.set(device.id,{...device,...access,managed_by_me:true,grants:device.grants})}state.devices=[...merged.values()];state.pending=pending.enrollments;$('devices').replaceChildren(...state.devices.filter(d=>!d.revoked_at).map(makeCard));if(!state.devices.some(d=>!d.revoked_at))$('devices').innerHTML='<div class="empty">No devices granted yet. Add a device to get started.</div>';$('summary').textContent=`${state.devices.filter(d=>!d.revoked_at).length} devices · ${state.devices.filter(d=>d.connected&&!d.revoked_at).length} online`;$('pendingCount').textContent=state.pending.length;$('pending').replaceChildren();for(const p of state.pending){const node=document.createElement('article');node.className='card';node.innerHTML=`<h2>${esc(p.metadata.display_name)}</h2><p>${esc(p.metadata.hostname)} · ${esc(p.metadata.platform)} · ${esc(p.metadata.architecture)}</p><span class="badge">${esc(p.metadata.local_ceiling)}</span><p class="mono">Code: ${esc(p.verification_code)}</p><p class="muted">Created: ${esc(time(p.created_at))}<br>Expires: ${esc(time(p.expires_at))}</p>`;const form=document.createElement('form');form.innerHTML='<label>Enter the code shown on the Agent<input name="code" required minlength="9" maxlength="9" autocomplete="off"></label><label><input name="grant" type="checkbox"> Grant this device to my account</label><button name="approve" value="true">Approve</button><button name="approve" value="false" class="danger">Reject</button>';form.onsubmit=e=>{e.preventDefault();action('/api/enrollment/pending/'+encodeURIComponent(p.id)+'/decision','POST',{code:form.elements.code.value.toUpperCase(),approve:e.submitter?.value==='true',grant_to_me:form.elements.grant.checked})};node.append(form);$('pending').append(node)}if(!state.pending.length)$('pending').innerHTML='<div class="empty">No pending enrollments reviewed by your account. Open the new machine’s enrollment link to review it.</div>';$('message').textContent=''}catch(e){error(e)}}
function row(label,value){return `<dt>${esc(label)}</dt><dd>${esc(value)}</dd>`}
function detail(d){$('detailTitle').textContent=d.display_name;const caps=d.capabilities||{};$('detailBody').innerHTML=`${permissionDisplay(d,true)}<dl>${row('Device ID',d.id)}${row('Hostname',d.hostname)}${row('OS / architecture',d.platform+' / '+d.architecture)}${row('Agent / protocol',d.agent_version+' / '+d.agent_protocol_version)}${row('Key generation',d.key_generation)}${row('Approved',time(d.approved_at))}${row('Connection',d.connected?'Online':'Offline')}${row('Last seen',time(d.last_seen))}${row('Update status',updateStatus(d))}</dl><h3>Capabilities</h3><div class="capabilities">${['filesystem','shell','process','git','docker','services','packages','system_power','browser','desktop','screen','keyboard','mouse','clipboard','agent_update','privileged_helper'].map(c=>`<span class="cap ${caps[c]===true?'available':''}">${esc(c.replaceAll('_',' '))}: ${caps[c]===true?'available':'unavailable'}</span>`).join('')}</div>`;if(d.managed_by_me){const section=document.createElement('section');section.className='section';section.innerHTML='<h3>Device access</h3><p class="muted">Only listed accounts can operate this device. Grants remain bounded by OAuth scopes, server permission and the local ceiling.</p>';for(const grant of d.grants||[]){const line=document.createElement('div');line.className='grant';const text=document.createElement('span');text.className='mono';text.textContent=grant.subject+' · '+grant.max_permission_profile;const remove=document.createElement('button');remove.textContent='Remove grant';remove.onclick=()=>action('/api/managed-devices/'+d.id+'/grants?subject='+encodeURIComponent(grant.subject),'DELETE');line.append(text,remove);section.append(line)}const form=document.createElement('form');form.innerHTML='<label>Account subject<input name="subject" required maxlength="255"></label><label>Grant<select name="profile"><option>READ_ONLY</option><option>STANDARD</option></select></label><button>Save explicit grant</button>';form.onsubmit=e=>{e.preventDefault();action('/api/managed-devices/'+d.id+'/grants','PUT',Object.fromEntries(new FormData(form)))};section.append(form);const rename=document.createElement('form');rename.innerHTML=`<label>Display name<input name="display_name" required maxlength="120" value="${esc(d.display_name)}"></label><button>Rename device</button>`;rename.onsubmit=e=>{e.preventDefault();action('/api/managed-devices/'+d.id,'PATCH',Object.fromEntries(new FormData(rename)))};section.append(rename);const revoke=document.createElement('button');revoke.textContent='Revoke device';revoke.className='danger';revoke.onclick=()=>{
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
};section.append(revoke);addDeviceDiagnostics(section,d);$('detailBody').append(section)}startLiveActivity(d);$('detail').showModal()}
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
$('close').onclick=()=>$('detail').close();$('refresh').onclick=refresh;
function tab(pending){$('devices').hidden=pending;$('pending').hidden=!pending;$('devicesTab').classList.toggle('selected',!pending);$('pendingTab').classList.toggle('selected',pending)}$('devicesTab').onclick=()=>tab(false);$('pendingTab').onclick=()=>tab(true);
$('add').onclick=()=>{
    $('detailTitle').textContent='Add a device';
    $('detailBody').innerHTML='<h3>Linux</h3><p>Run this on the new machine as your normal user:</p><pre id="linuxInstall"></pre><p>The installer detects your architecture, downloads and verifies the signed Agent, installs the user service, enables startup and reconnect, and begins enrollment.</p><ol><li>Open the enrollment link printed on the new machine.</li><li>Sign in.</li><li>Compare the verification code and device details.</li><li>Approve access to your account, normally STANDARD. The grant cannot exceed the machine’s local ceiling.</li></ol><p>After installation, use <code>commandcore-agent status</code> and <code>commandcore-agent activity</code> on that machine.</p><details><summary>Advanced / Agent already installed</summary><pre id="existingEnroll"></pre><p>Use this only when the Agent is already installed.</p></details><h3>Windows</h3><p class="muted">Not yet production-ready.</p><p class="muted">The Agent generates its private key locally. Enrollment approval expires after ten minutes.</p>';
    $('linuxInstall').textContent='curl -fsSL '+location.origin+'/install/linux | sh';
    $('existingEnroll').textContent='commandcore-agent enroll '+location.origin;
    $('detail').showModal();
};
$('signout').onclick=async()=>{try{await api('/api/session','DELETE');location.reload()}catch(e){error(e)}};
$('bootstrap').onsubmit=async e=>{e.preventDefault();try{await api('/api/session','POST',{token:$('token').value});$('token').value='';await init()}catch(e){error(e)}};
async function init(){try{state.session=await api('/api/session');$('account').textContent=state.session.subject;$('signout').hidden=false;$('login').hidden=true;$('dashboard').hidden=false;await refresh()}catch(e){$('login').hidden=false;const config=await api('/auth/config').catch(()=>({}));$('oauth').hidden=!config.oauth_available;error(e)}}init();setInterval(()=>{if(!document.hidden&&!$('dashboard').hidden&&$('pending').hidden&&!$('detail').open&&!['INPUT','SELECT','TEXTAREA'].includes(document.activeElement?.tagName))refresh()},10000);

let activityTimer;
let activityDevice;
function startLiveActivity(device){
    clearInterval(activityTimer);
    activityDevice=device.id;
    const section=document.createElement('section');
    section.className='section';
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
