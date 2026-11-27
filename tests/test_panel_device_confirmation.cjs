const assert=require("node:assert/strict");
const fs=require("node:fs");
const vm=require("node:vm");
const source=fs.readFileSync(__dirname+"/../apps/web/panel.js","utf8");
const begin=source.indexOf("let deviceConfirmationOpen=false;");
const end=source.indexOf("function displayPermissionName",begin);
assert(begin>=0&&end>begin);
function harness(){
    const nodes=[];
    function node(tag){
        const n={tag,children:[],events:{},open:false,disabled:false,value:"",
            append(...items){this.children.push(...items)},
            setAttribute(){},addEventListener(name,fn){this.events[name]=fn},
            showModal(){this.open=true},close(){this.open=false;this.events.close?.()},
            remove(){this.removed=true},focus(){this.focused=true}};
        nodes.push(n);return n;
    }
    const detail={open:true};
    const device={id:"fixture-id",display_name:"Fixture device",managed_by_me:true};
    const state={session:{subject:"fixture-owner",auth_kind:"oauth2-panel"},devices:[device]};
    const ctx={document:{createElement:node,body:node("body")},state,detailDeviceId:device.id,$:()=>detail};
    vm.createContext(ctx);
    vm.runInContext(source.slice(begin,end),ctx);
    const open=(requireName=true)=>ctx.confirmDeviceAction(device,{title:"Confirm",message:"Message",confirmLabel:"Approve",requireName});
    const controls=()=>({dialog:nodes.find(n=>n.tag==="dialog"&&!n.removed),input:nodes.find(n=>n.tag==="input"),cancel:nodes.find(n=>n.textContent==="Cancel"),approve:nodes.find(n=>n.textContent==="Approve")});
    return {ctx,state,device,detail,open,controls};
}
(async()=>{
    {
        const h=harness(),result=h.open(),{input,approve,cancel,dialog}=h.controls();
        assert(approve.disabled&&cancel.focused);
        input.value="wrong";input.events.input();assert(approve.disabled);
        input.value=h.device.display_name;input.events.input();assert(!approve.disabled);
        approve.onclick();assert.equal(await result,true);assert(dialog.removed);
    }
    {
        const h=harness(),result=h.open(),{approve}=h.controls();
        approve.onclick();assert.equal(await result,false); // even a direct handler call cannot skip typing
    }
    {
        const h=harness(),result=h.open(),{dialog}=h.controls();
        let prevented=false;dialog.events.cancel({preventDefault(){prevented=true}});
        assert(prevented);assert.equal(await result,false);
    }
    {
        const h=harness(),result=h.open(false),{approve}=h.controls();
        assert(!approve.disabled);assert.equal(await h.open(),false);
        approve.onclick();assert.equal(await result,true);
    }
    for(const mutate of [
        h=>h.state.session.subject="another-account",
        h=>h.ctx.detailDeviceId="another-device",
        h=>h.device.display_name="Renamed",
        h=>h.device.managed_by_me=false,
        h=>h.detail.open=false,
        h=>h.device.revoked_at="now",
    ]){
        const h=harness(),result=h.open(),{input,approve}=h.controls();
        input.value=h.device.display_name;input.events.input();mutate(h);
        approve.onclick();assert.equal(await result,false);
    }
    assert(source.includes("confirmLabel:'Remove access',requireName:self"));
    assert(source.includes("confirmLabel:'Revoke device',requireName:true"));
    console.log("PASS: 10 device confirmation scenarios; typed name, cancel, concurrent dialog, and stale account/device checks");
})().catch(error=>{console.error(error);process.exitCode=1});
