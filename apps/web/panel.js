const $=id=>document.getElementById(id);
const state={devices:[],pending:[],session:null};
const rank={READ_ONLY:0,STANDARD:1,FULL_CONTROL:2};
const esc=value=>String(value??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const time=value=>value?new Date(typeof value==='number'?value*1000:value).toLocaleString():'Never';
function effective(device){if(!device.is_owner&&!device.access_max_permission_profile)return 'No access';const scopes=state.session.scopes||[];const oauth=state.session.auth_kind==='oauth2-panel'?(scopes.includes('commandcore:full')?'FULL_CONTROL':scopes.includes('commandcore:standard')?'STANDARD':'READ_ONLY'):'FULL_CONTROL';const profiles=[device.permission_profile,device.access_max_permission_profile||'READ_ONLY',device.capabilities?.local_max_permission_profile||'STANDARD',oauth];return Object.keys(rank).find(p=>rank[p]===Math.min(...profiles.map(p=>rank[p]??0)))}
async function api(path,method='GET',body){const response=await fetch(path,{method,credentials:'same-origin',headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined});const data=await response.json().catch(()=>({}));if(response.status===401){$('login').hidden=false;$('dashboard').hidden=true;throw Error('Sign in to continue.')}if(!response.ok)throw Error(data.detail||'Request failed');return data}
function error(e){$('message').textContent=e.message}
function makeCard(device){const node=document.createElement('article');node.className='card';node.innerHTML=`<span class="status ${device.connected?'online':'offline'}">● ${device.revoked_at?'Revoked':device.connected?'Online':'Offline'}</span><h2>${esc(device.display_name)}</h2><div class="muted">${esc(device.hostname)}</div><p>${esc(device.platform)} · ${esc(device.architecture)}</p><span class="badge">Effective: ${esc(effective(device))}</span><div class="muted">Local ceiling: ${esc(device.capabilities?.local_max_permission_profile||'STANDARD')}</div><p class="muted">${esc(device.capabilities?.agent_implementation||'Agent')} ${esc(device.agent_version)}<br>Last seen: ${esc(time(device.last_seen))}<br>${device.agent_update_available?'Update available':'Update status: '+esc(device.capabilities?.agent_update_status||'not reported')}</p>`;const button=document.createElement('button');button.textContent='View device';button.onclick=()=>detail(device);node.append(button);return node}
async function refresh(){try{const [devices,managed,pending]=await Promise.all([api('/api/devices'),api('/api/managed-devices'),api('/api/enrollment/pending')]);const merged=new Map(devices.devices.map(d=>[d.id,d]));for(const device of managed.devices){const access=merged.get(device.id)||{};merged.set(device.id,{...device,...access,managed_by_me:true,grants:device.grants})}state.devices=[...merged.values()];state.pending=pending.enrollments;$('devices').replaceChildren(...state.devices.filter(d=>!d.revoked_at).map(makeCard));if(!state.devices.some(d=>!d.revoked_at))$('devices').innerHTML='<div class="empty">No devices granted yet. Add a device to get started.</div>';$('summary').textContent=`${state.devices.filter(d=>!d.revoked_at).length} devices · ${state.devices.filter(d=>d.connected&&!d.revoked_at).length} online`;$('pendingCount').textContent=state.pending.length;$('pending').replaceChildren();for(const p of state.pending){const node=document.createElement('article');node.className='card';node.innerHTML=`<h2>${esc(p.metadata.display_name)}</h2><p>${esc(p.metadata.hostname)} · ${esc(p.metadata.platform)} · ${esc(p.metadata.architecture)}</p><span class="badge">${esc(p.metadata.local_ceiling)}</span><p class="mono">Code: ${esc(p.verification_code)}</p><p class="muted">Created: ${esc(time(p.created_at))}<br>Expires: ${esc(time(p.expires_at))}</p>`;const form=document.createElement('form');form.innerHTML='<label>Enter the code shown on the Agent<input name="code" required minlength="9" maxlength="9" autocomplete="off"></label><label><input name="grant" type="checkbox"> Grant this device to my account</label><button name="approve" value="true">Approve</button><button name="approve" value="false" class="danger">Reject</button>';form.onsubmit=e=>{e.preventDefault();action('/api/enrollment/pending/'+encodeURIComponent(p.id)+'/decision','POST',{code:form.elements.code.value.toUpperCase(),approve:e.submitter?.value==='true',grant_to_me:form.elements.grant.checked})};node.append(form);$('pending').append(node)}if(!state.pending.length)$('pending').innerHTML='<div class="empty">No pending enrollments reviewed by your account. Open the new machine’s enrollment link to review it.</div>';$('message').textContent=''}catch(e){error(e)}}
function row(label,value){return `<dt>${esc(label)}</dt><dd>${esc(value)}</dd>`}
function detail(d){$('detailTitle').textContent=d.display_name;const caps=d.capabilities||{};$('detailBody').innerHTML=`<dl>${row('Device ID',d.id)}${row('Hostname',d.hostname)}${row('OS / architecture',d.platform+' / '+d.architecture)}${row('Agent / protocol',d.agent_version+' / '+d.agent_protocol_version)}${row('Key generation',d.key_generation)}${row('Approved',time(d.approved_at))}${row('Connection',d.connected?'Online':'Offline')}${row('Last seen',time(d.last_seen))}${row('Local ceiling',caps.local_max_permission_profile||'STANDARD')}${row('Server permission',d.permission_profile)}${row('Your grant',d.access_max_permission_profile||'No operation grant')}${row('Effective permission',effective(d))}${row('Update status',caps.agent_update_status||'Not reported')}</dl><h3>Capabilities</h3><div class="capabilities">${['filesystem','shell','process','git','docker','services','packages','system_power','browser','desktop','screen','keyboard','mouse','clipboard','agent_update','privileged_helper'].map(c=>`<span class="cap ${caps[c]===true?'available':''}">${esc(c.replaceAll('_',' '))}: ${caps[c]===true?'available':'unavailable'}</span>`).join('')}</div>`;if(d.managed_by_me){const section=document.createElement('section');section.className='section';section.innerHTML='<h3>Device access</h3><p class="muted">Only listed accounts can operate this device. Grants remain bounded by OAuth scopes and the local ceiling.</p>';for(const grant of d.grants||[]){const line=document.createElement('div');line.className='grant';const text=document.createElement('span');text.className='mono';text.textContent=grant.subject+' · '+grant.max_permission_profile;const remove=document.createElement('button');remove.textContent='Remove grant';remove.onclick=()=>action('/api/managed-devices/'+d.id+'/grants?subject='+encodeURIComponent(grant.subject),'DELETE');line.append(text,remove);section.append(line)}const form=document.createElement('form');form.innerHTML='<label>Account subject<input name="subject" required maxlength="255"></label><label>Grant<select name="profile"><option>READ_ONLY</option><option>STANDARD</option></select></label><button>Save explicit grant</button>';form.onsubmit=e=>{e.preventDefault();action('/api/managed-devices/'+d.id+'/grants','PUT',Object.fromEntries(new FormData(form)))};section.append(form);const rename=document.createElement('form');rename.innerHTML=`<label>Display name<input name="display_name" required maxlength="120" value="${esc(d.display_name)}"></label><button>Rename device</button>`;rename.onsubmit=e=>{e.preventDefault();action('/api/managed-devices/'+d.id,'PATCH',Object.fromEntries(new FormData(rename)))};section.append(rename);const revoke=document.createElement('button');revoke.textContent='Revoke device';revoke.className='danger';revoke.onclick=()=>{
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
