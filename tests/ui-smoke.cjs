const fs=require('node:fs'),assert=require('node:assert/strict');
class Element{constructor(tag,attrs,children){this.tag=tag;this.attrs=attrs||{};this.children=[];this.events={};this.style={};this.value=String(this.attrs.value??'');this.checked=!!this.attrs.checked;this.replaceChildren(children);if(tag==='select'){const c=this.children.find(c=>c?.attrs?.selected)||this.children[0];this.value=c?.attrs?.value||'';}}replaceChildren(...children){this.children=children.flat(Infinity).filter(c=>c!=null);}appendChild(c){this.children.push(c);return c;}setAttribute(k,v){this.attrs[k]=v;}addEventListener(k,v){this.events[k]=v;}querySelectorAll(s){let a=[];for(const c of this.children){if(c instanceof Element){if(s==='[data-mutation]'&&c.attrs['data-mutation'])a.push(c);a.push(...c.querySelectorAll(s));}}return a;}}
const E=(t,a,c)=>new Element(t,a,c),declarations=[];
const rpc={declare(spec){declarations.push(spec);return async()=>({});}},view={extend:o=>o},poll={add(){}},ui={addNotification(){},showModal(title,children){this.modal={title,children};},hideModal(){ui.modal=null;}};
const page=new Function('view','rpc','poll','ui','E',fs.readFileSync('files/www/luci-static/resources/view/routerbox/main.js','utf8'))(view,rpc,poll,ui,E);
const settings={enabled:false,interfaces:['br-lan'],ipv6:false,mtu:1400,failure:'block',final:'direct',storage:'flash',core_url:'',core_sha:'',core_size:0,rules_interval:24,dns_mode:'stable',dns_strategy:'prefer_ipv4',dns_cache:true,bootstrap:'1.1.1.1',subscriptions:[{id:'sub',name:'Altflow',enabled:true,url:'https://example.com/subscription',interval:24}],groups:[{id:'main',name:'Main',nodes:['a','b'],mode:'fastest',selected:'a',interval:300,timeout:5,tolerance:50,hold:300,failures:3,recovery:2,window:30,test_url:'https://example.com/',failure:'block'}],rules:[{name:'YouTube',enabled:true,categories:['youtube'],domains:[],ips:[],sources:[],macs:[],id:'youtube',target:'vpn',dns:'',nodes:[],mode:'stable'}],dns:[{id:'cf',name:'Cloudflare',address:'https://1.1.1.1/dns-query',detour:'direct'}]};
const state={settings,nodes:[{id:'a',name:'Server A',subscription:'sub',protocol:'vless',server:'example.com',port:443},{id:'b',name:'Server B',subscription:'sub',protocol:'trojan',server:'example.net',port:443}],devices:[{name:'TV',ip:'192.168.1.2',mac:'00:11:22:33:44:55'}],catalogue:{categories:['youtube','google','telegram']},selections:{main:'a'},events:['Ready'],storage:{flash_free:10e6,ram_free:100e6,controller_heap:2e6},job:{},traffic:{upload:100,download:200},running:true,core_version:'test'};
assert(page.render(state) instanceof Element);
for(const tab of ['overview','subscriptions','servers','routing','dns','settings','updates','logs']){page.showTab(tab);assert(page.content.children.length===1,tab);}
assert.deepEqual(declarations.find(d=>d.method==='state').expect,{'':{}});
assert.deepEqual(declarations.find(d=>d.method==='save').params,['data']);
page.busy=true;page.setBusy();assert(page.root.querySelectorAll('[data-mutation]').every(b=>b.disabled));

page.busy=false;
page.subscriptionDialog();assert.equal(ui.modal.title,'Добавить подписку');
page.ruleDialog();assert.equal(ui.modal.title,'Добавить маршрут');

page.ruleDialog({...settings.rules[0],categories:['allow-youtube']},0);
function descendants(node){if(!(node instanceof Element))return [];return [node,...node.children.flatMap(descendants)];}
const dialogNodes=ui.modal.children.flatMap(descendants);
const youtubeLabel=dialogNodes.find(n=>n.tag==='label'&&n.attrs.title==='allow-domains'&&n.children.some(c=>c instanceof Element&&c.children.includes('YouTube')));
const youtubeCheck=youtubeLabel.children.find(n=>n instanceof Element&&n.tag==='input');assert(youtubeCheck.checked);
const selectedChip=dialogNodes.find(n=>n.tag==='span'&&n.attrs.class==='rb-chip'&&n.children.some(c=>c instanceof Element&&c.children.includes('YouTube')));
selectedChip.children.find(n=>n instanceof Element&&n.tag==='button').attrs.click();assert(!youtubeCheck.checked,'removing chip must uncheck service');

page.draft.final='vpn';page.showTab('routing');
page.state.nodes[0].health=null;page.state.catalogue=null;page.state.events=null;page.state=normalizeForTest(page.state);
function normalizeForTest(st){st.catalogue=st.catalogue||{};st.events=st.events||[];return st;}
for(const tab of ['overview','subscriptions','servers','routing','dns','settings','updates','logs'])page.showTab(tab);
const source=fs.readFileSync('files/www/luci-static/resources/view/routerbox/main.js','utf8');
assert(!source.includes("['groups','Группы серверов']"));
assert(!source.includes("input(p.url,function(v){p.url=v;},'password')"));
if(process.env.ROUTERBOX_WRITE_FIXTURE)fs.writeFileSync('build/ui-fixture.json',JSON.stringify(state));
console.log('LuCI views, subscription/routing dialogs, null state and job lock: OK');

page.busy=false;page.subscriptionDialog(settings.subscriptions[0]);
const subscriptionFields=ui.modal.children.flatMap(descendants);
function labelText(node){return node.children.filter(c=>c instanceof Element&&c.tag==='span').flatMap(c=>c.children).join('');}
for(const name of ['Загрузка подписки','User-Agent','Фильтр серверов','Слова и регулярные выражения'])assert(subscriptionFields.some(n=>n.tag==='label'&&labelText(n)===name),name);
const patternField=subscriptionFields.find(n=>n.tag==='label'&&labelText(n)==='Слова и регулярные выражения');
const patternControl=patternField.children.find(n=>n.tag==='textarea');patternControl.value='(?i)de.{1,3}\nnetherlands';patternControl.events.input();
page.ruleDialog({...settings.rules[0],separate_udp:true,udp_nodes:['b']},0);
assert(ui.modal.children.flatMap(descendants).some(n=>n.tag==='strong'&&n.children.includes('Серверы для UDP')));
page.showTab('dns');assert(descendants(page.content).some(n=>n.tag==='label'&&labelText(n)==='Таймаут DNS, секунд'));
console.log('Subscription filters, UDP pool and DNS controls: OK');
