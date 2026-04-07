<!DOCTYPE html>
<html lang="en">
<head>
                                <meta name="robots" content="index, follow" />
                        <script type="text/javascript" nonce="">(window.NREUM||(NREUM={})).init={ajax:{deny_list:["bam.nr-data.net"]}};(window.NREUM||(NREUM={})).loader_config={licenseKey:"5364be9000",applicationID:"523907688"};;/*! For license information please see nr-loader-rum-1.298.0.min.js.LICENSE.txt */
(()=>{var e,t,r={122:(e,t,r)=>{"use strict";r.d(t,{a:()=>i});var n=r(944);function i(e,t){try{if(!e||"object"!=typeof e)return(0,n.R)(3);if(!t||"object"!=typeof t)return(0,n.R)(4);const r=Object.create(Object.getPrototypeOf(t),Object.getOwnPropertyDescriptors(t)),a=0===Object.keys(r).length?e:r;for(let s in a)if(void 0!==e[s])try{if(null===e[s]){r[s]=null;continue}Array.isArray(e[s])&&Array.isArray(t[s])?r[s]=Array.from(new Set([...e[s],...t[s]])):"object"==typeof e[s]&&"object"==typeof t[s]?r[s]=i(e[s],t[s]):r[s]=e[s]}catch(e){r[s]||(0,n.R)(1,e)}return r}catch(e){(0,n.R)(2,e)}}},555:(e,t,r)=>{"use strict";r.d(t,{D:()=>o,f:()=>s});var n=r(384),i=r(122);const a={beacon:n.NT.beacon,errorBeacon:n.NT.errorBeacon,licenseKey:void 0,applicationID:void 0,sa:void 0,queueTime:void 0,applicationTime:void 0,ttGuid:void 0,user:void 0,account:void 0,product:void 0,extra:void 0,jsAttributes:{},userAttributes:void 0,atts:void 0,transactionName:void 0,tNamePlain:void 0};function s(e){try{return!!e.licenseKey&&!!e.errorBeacon&&!!e.applicationID}catch(e){return!1}}const o=e=>(0,i.a)(e,a)},699:(e,t,r)=>{"use strict";r.d(t,{It:()=>i,No:()=>n,qh:()=>s,uh:()=>a});const n=16e3,i=1e6,a="NR_CONTAINER_AGENT",s="SESSION_ERROR"},324:(e,t,r)=>{"use strict";r.d(t,{F3:()=>i,Xs:()=>a,xv:()=>n});const n="1.298.0",i="PROD",a="CDN"},154:(e,t,r)=>{"use strict";r.d(t,{OF:()=>c,RI:()=>i,WN:()=>d,bv:()=>a,gm:()=>s,mw:()=>o,sb:()=>u});var n=r(863);const i="undefined"!=typeof window&&!!window.document,a="undefined"!=typeof WorkerGlobalScope&&("undefined"!=typeof self&&self instanceof WorkerGlobalScope&&self.navigator instanceof WorkerNavigator||"undefined"!=typeof globalThis&&globalThis instanceof WorkerGlobalScope&&globalThis.navigator instanceof WorkerNavigator),s=i?window:"undefined"!=typeof WorkerGlobalScope&&("undefined"!=typeof self&&self instanceof WorkerGlobalScope&&self||"undefined"!=typeof globalThis&&globalThis instanceof WorkerGlobalScope&&globalThis),o=Boolean("hidden"===s?.document?.visibilityState),c=/iPad|iPhone|iPod/.test(s.navigator?.userAgent),u=c&&"undefined"==typeof SharedWorker,d=((()=>{const e=s.navigator?.userAgent?.match(/Firefox[/\s](\d+\.\d+)/);Array.isArray(e)&&e.length>=2&&e[1]})(),Date.now()-(0,n.t)())},241:(e,t,r)=>{"use strict";r.d(t,{W:()=>a});var n=r(154);const i="newrelic";function a(e={}){try{n.gm.dispatchEvent(new CustomEvent(i,{detail:e}))}catch(e){}}},687:(e,t,r)=>{"use strict";r.d(t,{Ak:()=>u,Ze:()=>f,x3:()=>d});var n=r(241),i=r(836),a=r(606),s=r(860),o=r(646);const c={};function u(e,t){const r={staged:!1,priority:s.P3[t]||0};l(e),c[e].get(t)||c[e].set(t,r)}function d(e,t){e&&c[e]&&(c[e].get(t)&&c[e].delete(t),p(e,t,!1),c[e].size&&g(e))}function l(e){if(!e)throw new Error("agentIdentifier required");c[e]||(c[e]=new Map)}function f(e="",t="feature",r=!1){if(l(e),!e||!c[e].get(t)||r)return p(e,t);c[e].get(t).staged=!0,g(e)}function g(e){const t=Array.from(c[e]);t.every((([e,t])=>t.staged))&&(t.sort(((e,t)=>e[1].priority-t[1].priority)),t.forEach((([t])=>{c[e].delete(t),p(e,t)})))}function p(e,t,r=!0){const s=e?i.ee.get(e):i.ee,c=a.i.handlers;if(!s.aborted&&s.backlog&&c){if((0,n.W)({agentIdentifier:e,type:"lifecycle",name:"drain",feature:t}),r){const e=s.backlog[t],r=c[t];if(r){for(let t=0;e&&t<e.length;++t)m(e[t],r);Object.entries(r).forEach((([e,t])=>{Object.values(t||{}).forEach((t=>{t[0]?.on&&t[0]?.context()instanceof o.y&&t[0].on(e,t[1])}))}))}}s.isolatedBacklog||delete c[t],s.backlog[t]=null,s.emit("drain-"+t,[])}}function m(e,t){var r=e[1];Object.values(t[r]||{}).forEach((t=>{var r=e[0];if(t[0]===r){var n=t[1],i=e[3],a=e[2];n.apply(i,a)}}))}},836:(e,t,r)=>{"use strict";r.d(t,{P:()=>o,ee:()=>c});var n=r(384),i=r(990),a=r(646),s=r(607);const o="nr@context:".concat(s.W),c=function e(t,r){var n={},s={},d={},l=!1;try{l=16===r.length&&u.initializedAgents?.[r]?.runtime.isolatedBacklog}catch(e){}var f={on:p,addEventListener:p,removeEventListener:function(e,t){var r=n[e];if(!r)return;for(var i=0;i<r.length;i++)r[i]===t&&r.splice(i,1)},emit:function(e,r,n,i,a){!1!==a&&(a=!0);if(c.aborted&&!i)return;t&&a&&t.emit(e,r,n);var o=g(n);m(e).forEach((e=>{e.apply(o,r)}));var u=v()[s[e]];u&&u.push([f,e,r,o]);return o},get:h,listeners:m,context:g,buffer:function(e,t){const r=v();if(t=t||"feature",f.aborted)return;Object.entries(e||{}).forEach((([e,n])=>{s[n]=t,t in r||(r[t]=[])}))},abort:function(){f._aborted=!0,Object.keys(f.backlog).forEach((e=>{delete f.backlog[e]}))},isBuffering:function(e){return!!v()[s[e]]},debugId:r,backlog:l?{}:t&&"object"==typeof t.backlog?t.backlog:{},isolatedBacklog:l};return Object.defineProperty(f,"aborted",{get:()=>{let e=f._aborted||!1;return e||(t&&(e=t.aborted),e)}}),f;function g(e){return e&&e instanceof a.y?e:e?(0,i.I)(e,o,(()=>new a.y(o))):new a.y(o)}function p(e,t){n[e]=m(e).concat(t)}function m(e){return n[e]||[]}function h(t){return d[t]=d[t]||e(f,t)}function v(){return f.backlog}}(void 0,"globalEE"),u=(0,n.Zm)();u.ee||(u.ee=c)},646:(e,t,r)=>{"use strict";r.d(t,{y:()=>n});class n{constructor(e){this.contextId=e}}},908:(e,t,r)=>{"use strict";r.d(t,{d:()=>n,p:()=>i});var n=r(836).ee.get("handle");function i(e,t,r,i,a){a?(a.buffer([e],i),a.emit(e,t,r)):(n.buffer([e],i),n.emit(e,t,r))}},606:(e,t,r)=>{"use strict";r.d(t,{i:()=>a});var n=r(908);a.on=s;var i=a.handlers={};function a(e,t,r,a){s(a||n.d,i,e,t,r)}function s(e,t,r,i,a){a||(a="feature"),e||(e=n.d);var s=t[a]=t[a]||{};(s[r]=s[r]||[]).push([e,i])}},878:(e,t,r)=>{"use strict";function n(e,t){return{capture:e,passive:!1,signal:t}}function i(e,t,r=!1,i){window.addEventListener(e,t,n(r,i))}function a(e,t,r=!1,i){document.addEventListener(e,t,n(r,i))}r.d(t,{DD:()=>a,jT:()=>n,sp:()=>i})},607:(e,t,r)=>{"use strict";r.d(t,{W:()=>n});const n=(0,r(566).bz)()},566:(e,t,r)=>{"use strict";r.d(t,{LA:()=>o,bz:()=>s});var n=r(154);const i="xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";function a(e,t){return e?15&e[t]:16*Math.random()|0}function s(){const e=n.gm?.crypto||n.gm?.msCrypto;let t,r=0;return e&&e.getRandomValues&&(t=e.getRandomValues(new Uint8Array(30))),i.split("").map((e=>"x"===e?a(t,r++).toString(16):"y"===e?(3&a()|8).toString(16):e)).join("")}function o(e){const t=n.gm?.crypto||n.gm?.msCrypto;let r,i=0;t&&t.getRandomValues&&(r=t.getRandomValues(new Uint8Array(e)));const s=[];for(var o=0;o<e;o++)s.push(a(r,i++).toString(16));return s.join("")}},614:(e,t,r)=>{"use strict";r.d(t,{BB:()=>s,H3:()=>n,g:()=>u,iL:()=>c,tS:()=>o,uh:()=>i,wk:()=>a});const n="NRBA",i="SESSION",a=144e5,s=18e5,o={STARTED:"session-started",PAUSE:"session-pause",RESET:"session-reset",RESUME:"session-resume",UPDATE:"session-update"},c={SAME_TAB:"same-tab",CROSS_TAB:"cross-tab"},u={OFF:0,FULL:1,ERROR:2}},863:(e,t,r)=>{"use strict";function n(){return Math.floor(performance.now())}r.d(t,{t:()=>n})},944:(e,t,r)=>{"use strict";r.d(t,{R:()=>i});var n=r(241);function i(e,t){"function"==typeof console.debug&&(console.debug("New Relic Warning: https://github.com/newrelic/newrelic-browser-agent/blob/main/docs/warning-codes.md#".concat(e),t),(0,n.W)({agentIdentifier:null,drained:null,type:"data",name:"warn",feature:"warn",data:{code:e,secondary:t}}))}},701:(e,t,r)=>{"use strict";r.d(t,{B:()=>a,t:()=>s});var n=r(241);const i=new Set,a={};function s(e,t){const r=t.agentIdentifier;a[r]??={},e&&"object"==typeof e&&(i.has(r)||(t.ee.emit("rumresp",[e]),a[r]=e,i.add(r),(0,n.W)({agentIdentifier:r,loaded:!0,drained:!0,type:"lifecycle",name:"load",feature:void 0,data:e})))}},990:(e,t,r)=>{"use strict";r.d(t,{I:()=>i});var n=Object.prototype.hasOwnProperty;function i(e,t,r){if(n.call(e,t))return e[t];var i=r();if(Object.defineProperty&&Object.keys)try{return Object.defineProperty(e,t,{value:i,writable:!0,enumerable:!1}),i}catch(e){}return e[t]=i,i}},389:(e,t,r)=>{"use strict";function n(e,t=500,r={}){const n=r?.leading||!1;let i;return(...r)=>{n&&void 0===i&&(e.apply(this,r),i=setTimeout((()=>{i=clearTimeout(i)}),t)),n||(clearTimeout(i),i=setTimeout((()=>{e.apply(this,r)}),t))}}function i(e){let t=!1;return(...r)=>{t||(t=!0,e.apply(this,r))}}r.d(t,{J:()=>i,s:()=>n})},910:(e,t,r)=>{"use strict";r.d(t,{i:()=>a});var n=r(944);const i=new Map;function a(...e){return e.every((e=>{if(i.has(e))return i.get(e);const t="function"==typeof e&&e.toString().includes("[native code]");return t||(0,n.R)(64,e?.name||e?.toString()),i.set(e,t),t}))}},289:(e,t,r)=>{"use strict";r.d(t,{GG:()=>a,Qr:()=>o,sB:()=>s});var n=r(878);function i(){return"undefined"==typeof document||"complete"===document.readyState}function a(e,t){if(i())return e();(0,n.sp)("load",e,t)}function s(e){if(i())return e();(0,n.DD)("DOMContentLoaded",e)}function o(e){if(i())return e();(0,n.sp)("popstate",e)}},384:(e,t,r)=>{"use strict";r.d(t,{NT:()=>s,US:()=>d,Zm:()=>o,bQ:()=>u,dV:()=>c,pV:()=>l});var n=r(154),i=r(863),a=r(910);const s={beacon:"bam.nr-data.net",errorBeacon:"bam.nr-data.net"};function o(){return n.gm.NREUM||(n.gm.NREUM={}),void 0===n.gm.newrelic&&(n.gm.newrelic=n.gm.NREUM),n.gm.NREUM}function c(){let e=o();return e.o||(e.o={ST:n.gm.setTimeout,SI:n.gm.setImmediate||n.gm.setInterval,CT:n.gm.clearTimeout,XHR:n.gm.XMLHttpRequest,REQ:n.gm.Request,EV:n.gm.Event,PR:n.gm.Promise,MO:n.gm.MutationObserver,FETCH:n.gm.fetch,WS:n.gm.WebSocket},(0,a.i)(...Object.values(e.o))),e}function u(e,t){let r=o();r.initializedAgents??={},t.initializedAt={ms:(0,i.t)(),date:new Date},r.initializedAgents[e]=t}function d(e,t){o()[e]=t}function l(){return function(){let e=o();const t=e.info||{};e.info={beacon:s.beacon,errorBeacon:s.errorBeacon,...t}}(),function(){let e=o();const t=e.init||{};e.init={...t}}(),c(),function(){let e=o();const t=e.loader_config||{};e.loader_config={...t}}(),o()}},843:(e,t,r)=>{"use strict";r.d(t,{u:()=>i});var n=r(878);function i(e,t=!1,r,i){(0,n.DD)("visibilitychange",(function(){if(t)return void("hidden"===document.visibilityState&&e());e(document.visibilityState)}),r,i)}},773:(e,t,r)=>{"use strict";r.d(t,{z_:()=>a,XG:()=>o,TZ:()=>n,rs:()=>i,xV:()=>s});r(154),r(566),r(384);const n=r(860).K7.metrics,i="sm",a="cm",s="storeSupportabilityMetrics",o="storeEventMetrics"},630:(e,t,r)=>{"use strict";r.d(t,{T:()=>n});const n=r(860).K7.pageViewEvent},782:(e,t,r)=>{"use strict";r.d(t,{T:()=>n});const n=r(860).K7.pageViewTiming},234:(e,t,r)=>{"use strict";r.d(t,{W:()=>a});var n=r(836),i=r(687);class a{constructor(e,t){this.agentIdentifier=e,this.ee=n.ee.get(e),this.featureName=t,this.blocked=!1}deregisterDrain(){(0,i.x3)(this.agentIdentifier,this.featureName)}}},741:(e,t,r)=>{"use strict";r.d(t,{W:()=>a});var n=r(944),i=r(261);class a{#e(e,...t){if(this[e]!==a.prototype[e])return this[e](...t);(0,n.R)(35,e)}addPageAction(e,t){return this.#e(i.hG,e,t)}register(e){return this.#e(i.eY,e)}recordCustomEvent(e,t){return this.#e(i.fF,e,t)}setPageViewName(e,t){return this.#e(i.Fw,e,t)}setCustomAttribute(e,t,r){return this.#e(i.cD,e,t,r)}noticeError(e,t){return this.#e(i.o5,e,t)}setUserId(e){return this.#e(i.Dl,e)}setApplicationVersion(e){return this.#e(i.nb,e)}setErrorHandler(e){return this.#e(i.bt,e)}addRelease(e,t){return this.#e(i.k6,e,t)}log(e,t){return this.#e(i.$9,e,t)}start(){return this.#e(i.d3)}finished(e){return this.#e(i.BL,e)}recordReplay(){return this.#e(i.CH)}pauseReplay(){return this.#e(i.Tb)}addToTrace(e){return this.#e(i.U2,e)}setCurrentRouteName(e){return this.#e(i.PA,e)}interaction(){return this.#e(i.dT)}wrapLogger(e,t,r){return this.#e(i.Wb,e,t,r)}measure(e,t){return this.#e(i.V1,e,t)}}},261:(e,t,r)=>{"use strict";r.d(t,{$9:()=>u,BL:()=>o,CH:()=>g,Dl:()=>_,Fw:()=>y,PA:()=>h,Pl:()=>n,Tb:()=>l,U2:()=>a,V1:()=>k,Wb:()=>x,bt:()=>b,cD:()=>v,d3:()=>w,dT:()=>c,eY:()=>p,fF:()=>f,hG:()=>i,k6:()=>s,nb:()=>m,o5:()=>d});const n="api-",i="addPageAction",a="addToTrace",s="addRelease",o="finished",c="interaction",u="log",d="noticeError",l="pauseReplay",f="recordCustomEvent",g="recordReplay",p="register",m="setApplicationVersion",h="setCurrentRouteName",v="setCustomAttribute",b="setErrorHandler",y="setPageViewName",_="setUserId",w="start",x="wrapLogger",k="measure"},163:(e,t,r)=>{"use strict";r.d(t,{j:()=>E});var n=r(384),i=r(741);var a=r(555);r(860).K7.genericEvents;const s="experimental.marks",o="experimental.measures",c="experimental.resources",u=e=>{if(!e||"string"!=typeof e)return!1;try{document.createDocumentFragment().querySelector(e)}catch{return!1}return!0};var d=r(614),l=r(944),f=r(122);const g="[data-nr-mask]",p=e=>(0,f.a)(e,(()=>{const e={feature_flags:[],experimental:{marks:!1,measures:!1,resources:!1},mask_selector:"*",block_selector:"[data-nr-block]",mask_input_options:{color:!1,date:!1,"datetime-local":!1,email:!1,month:!1,number:!1,range:!1,search:!1,tel:!1,text:!1,time:!1,url:!1,week:!1,textarea:!1,select:!1,password:!0}};return{ajax:{deny_list:void 0,block_internal:!0,enabled:!0,autoStart:!0},api:{allow_registered_children:!0,duplicate_registered_data:!1},distributed_tracing:{enabled:void 0,exclude_newrelic_header:void 0,cors_use_newrelic_header:void 0,cors_use_tracecontext_headers:void 0,allowed_origins:void 0},get feature_flags(){return e.feature_flags},set feature_flags(t){e.feature_flags=t},generic_events:{enabled:!0,autoStart:!0},harvest:{interval:30},jserrors:{enabled:!0,autoStart:!0},logging:{enabled:!0,autoStart:!0},metrics:{enabled:!0,autoStart:!0},obfuscate:void 0,page_action:{enabled:!0},page_view_event:{enabled:!0,autoStart:!0},page_view_timing:{enabled:!0,autoStart:!0},performance:{get capture_marks(){return e.feature_flags.includes(s)||e.experimental.marks},set capture_marks(t){e.experimental.marks=t},get capture_measures(){return e.feature_flags.includes(o)||e.experimental.measures},set capture_measures(t){e.experimental.measures=t},capture_detail:!0,resources:{get enabled(){return e.feature_flags.includes(c)||e.experimental.resources},set enabled(t){e.experimental.resources=t},asset_types:[],first_party_domains:[],ignore_newrelic:!0}},privacy:{cookies_enabled:!0},proxy:{assets:void 0,beacon:void 0},session:{expiresMs:d.wk,inactiveMs:d.BB},session_replay:{autoStart:!0,enabled:!1,preload:!1,sampling_rate:10,error_sampling_rate:100,collect_fonts:!1,inline_images:!1,fix_stylesheets:!0,mask_all_inputs:!0,get mask_text_selector(){return e.mask_selector},set mask_text_selector(t){u(t)?e.mask_selector="".concat(t,",").concat(g):""===t||null===t?e.mask_selector=g:(0,l.R)(5,t)},get block_class(){return"nr-block"},get ignore_class(){return"nr-ignore"},get mask_text_class(){return"nr-mask"},get block_selector(){return e.block_selector},set block_selector(t){u(t)?e.block_selector+=",".concat(t):""!==t&&(0,l.R)(6,t)},get mask_input_options(){return e.mask_input_options},set mask_input_options(t){t&&"object"==typeof t?e.mask_input_options={...t,password:!0}:(0,l.R)(7,t)}},session_trace:{enabled:!0,autoStart:!0},soft_navigations:{enabled:!0,autoStart:!0},spa:{enabled:!0,autoStart:!0},ssl:void 0,user_actions:{enabled:!0,elementAttributes:["id","className","tagName","type"]}}})());var m=r(154),h=r(324);let v=0;const b={buildEnv:h.F3,distMethod:h.Xs,version:h.xv,originTime:m.WN},y={appMetadata:{},customTransaction:void 0,denyList:void 0,disabled:!1,entityManager:void 0,harvester:void 0,isolatedBacklog:!1,isRecording:!1,loaderType:void 0,maxBytes:3e4,obfuscator:void 0,onerror:void 0,ptid:void 0,releaseIds:{},session:void 0,timeKeeper:void 0,jsAttributesMetadata:{bytes:0},get harvestCount(){return++v}},_=e=>{const t=(0,f.a)(e,y),r=Object.keys(b).reduce(((e,t)=>(e[t]={value:b[t],writable:!1,configurable:!0,enumerable:!0},e)),{});return Object.defineProperties(t,r)};var w=r(701);const x=e=>{const t=e.startsWith("http");e+="/",r.p=t?e:"https://"+e};var k=r(836),S=r(241);const A={accountID:void 0,trustKey:void 0,agentID:void 0,licenseKey:void 0,applicationID:void 0,xpid:void 0},R=e=>(0,f.a)(e,A),T=new Set;function E(e,t={},r,s){let{init:o,info:c,loader_config:u,runtime:d={},exposed:l=!0}=t;if(!c){const e=(0,n.pV)();o=e.init,c=e.info,u=e.loader_config}e.init=p(o||{}),e.loader_config=R(u||{}),c.jsAttributes??={},m.bv&&(c.jsAttributes.isWorker=!0),e.info=(0,a.D)(c);const f=e.init,g=[c.beacon,c.errorBeacon];T.has(e.agentIdentifier)||(f.proxy.assets&&(x(f.proxy.assets),g.push(f.proxy.assets)),f.proxy.beacon&&g.push(f.proxy.beacon),function(e){const t=(0,n.pV)();Object.getOwnPropertyNames(i.W.prototype).forEach((r=>{const n=i.W.prototype[r];if("function"!=typeof n||"constructor"===n)return;let a=t[r];e[r]&&!1!==e.exposed&&"micro-agent"!==e.runtime?.loaderType&&(t[r]=(...t)=>{const n=e[r](...t);return a?a(...t):n})}))}(e),(0,n.US)("activatedFeatures",w.B),e.runSoftNavOverSpa&&=!0===f.soft_navigations.enabled&&f.feature_flags.includes("soft_nav")),d.denyList=[...f.ajax.deny_list||[],...f.ajax.block_internal?g:[]],d.ptid=e.agentIdentifier,d.loaderType=r,e.runtime=_(d),T.has(e.agentIdentifier)||(e.ee=k.ee.get(e.agentIdentifier),e.exposed=l,(0,S.W)({agentIdentifier:e.agentIdentifier,drained:!!w.B?.[e.agentIdentifier],type:"lifecycle",name:"initialize",feature:void 0,data:e.config})),T.add(e.agentIdentifier)}},374:(e,t,r)=>{r.nc=(()=>{try{return document?.currentScript?.nonce}catch(e){}return""})()},860:(e,t,r)=>{"use strict";r.d(t,{$J:()=>d,K7:()=>c,P3:()=>u,XX:()=>i,Yy:()=>o,df:()=>a,qY:()=>n,v4:()=>s});const n="events",i="jserrors",a="browser/blobs",s="rum",o="browser/logs",c={ajax:"ajax",genericEvents:"generic_events",jserrors:i,logging:"logging",metrics:"metrics",pageAction:"page_action",pageViewEvent:"page_view_event",pageViewTiming:"page_view_timing",sessionReplay:"session_replay",sessionTrace:"session_trace",softNav:"soft_navigations",spa:"spa"},u={[c.pageViewEvent]:1,[c.pageViewTiming]:2,[c.metrics]:3,[c.jserrors]:4,[c.spa]:5,[c.ajax]:6,[c.sessionTrace]:7,[c.softNav]:8,[c.sessionReplay]:9,[c.logging]:10,[c.genericEvents]:11},d={[c.pageViewEvent]:s,[c.pageViewTiming]:n,[c.ajax]:n,[c.spa]:n,[c.softNav]:n,[c.metrics]:i,[c.jserrors]:i,[c.sessionTrace]:a,[c.sessionReplay]:a,[c.logging]:o,[c.genericEvents]:"ins"}}},n={};function i(e){var t=n[e];if(void 0!==t)return t.exports;var a=n[e]={exports:{}};return r[e](a,a.exports,i),a.exports}i.m=r,i.d=(e,t)=>{for(var r in t)i.o(t,r)&&!i.o(e,r)&&Object.defineProperty(e,r,{enumerable:!0,get:t[r]})},i.f={},i.e=e=>Promise.all(Object.keys(i.f).reduce(((t,r)=>(i.f[r](e,t),t)),[])),i.u=e=>"nr-rum-1.298.0.min.js",i.o=(e,t)=>Object.prototype.hasOwnProperty.call(e,t),e={},t="NRBA-1.298.0.PROD:",i.l=(r,n,a,s)=>{if(e[r])e[r].push(n);else{var o,c;if(void 0!==a)for(var u=document.getElementsByTagName("script"),d=0;d<u.length;d++){var l=u[d];if(l.getAttribute("src")==r||l.getAttribute("data-webpack")==t+a){o=l;break}}if(!o){c=!0;var f={296:"sha512-7r59xFei/wYH/qDe7AmsUKR7NqbaD4hdacClEUAHBqKIhkH+j3LpuCNDcJ6TJ5mHwqOg0To3xAGIeaCDdga6dQ=="};(o=document.createElement("script")).charset="utf-8",o.timeout=120,i.nc&&o.setAttribute("nonce",i.nc),o.setAttribute("data-webpack",t+a),o.src=r,0!==o.src.indexOf(window.location.origin+"/")&&(o.crossOrigin="anonymous"),f[s]&&(o.integrity=f[s])}e[r]=[n];var g=(t,n)=>{o.onerror=o.onload=null,clearTimeout(p);var i=e[r];if(delete e[r],o.parentNode&&o.parentNode.removeChild(o),i&&i.forEach((e=>e(n))),t)return t(n)},p=setTimeout(g.bind(null,void 0,{type:"timeout",target:o}),12e4);o.onerror=g.bind(null,o.onerror),o.onload=g.bind(null,o.onload),c&&document.head.appendChild(o)}},i.r=e=>{"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},i.p="https://js-agent.newrelic.com/",(()=>{var e={374:0,840:0};i.f.j=(t,r)=>{var n=i.o(e,t)?e[t]:void 0;if(0!==n)if(n)r.push(n[2]);else{var a=new Promise(((r,i)=>n=e[t]=[r,i]));r.push(n[2]=a);var s=i.p+i.u(t),o=new Error;i.l(s,(r=>{if(i.o(e,t)&&(0!==(n=e[t])&&(e[t]=void 0),n)){var a=r&&("load"===r.type?"missing":r.type),s=r&&r.target&&r.target.src;o.message="Loading chunk "+t+" failed.\n("+a+": "+s+")",o.name="ChunkLoadError",o.type=a,o.request=s,n[1](o)}}),"chunk-"+t,t)}};var t=(t,r)=>{var n,a,[s,o,c]=r,u=0;if(s.some((t=>0!==e[t]))){for(n in o)i.o(o,n)&&(i.m[n]=o[n]);if(c)c(i)}for(t&&t(r);u<s.length;u++)a=s[u],i.o(e,a)&&e[a]&&e[a][0](),e[a]=0},r=self["webpackChunk:NRBA-1.298.0.PROD"]=self["webpackChunk:NRBA-1.298.0.PROD"]||[];r.forEach(t.bind(null,0)),r.push=t.bind(null,r.push.bind(r))})(),(()=>{"use strict";i(374);var e=i(566),t=i(741);class r extends t.W{agentIdentifier=(0,e.LA)(16)}var n=i(860);const a=Object.values(n.K7);var s=i(163);var o=i(908),c=i(863),u=i(261),d=i(241),l=i(944),f=i(701),g=i(773);function p(e,t,i,a){const s=a||i;!s||s[e]&&s[e]!==r.prototype[e]||(s[e]=function(){(0,o.p)(g.xV,["API/"+e+"/called"],void 0,n.K7.metrics,i.ee),(0,d.W)({agentIdentifier:i.agentIdentifier,drained:!!f.B?.[i.agentIdentifier],type:"data",name:"api",feature:u.Pl+e,data:{}});try{return t.apply(this,arguments)}catch(e){(0,l.R)(23,e)}})}function m(e,t,r,n,i){const a=e.info;null===r?delete a.jsAttributes[t]:a.jsAttributes[t]=r,(i||null===r)&&(0,o.p)(u.Pl+n,[(0,c.t)(),t,r],void 0,"session",e.ee)}var h=i(687),v=i(234),b=i(289),y=i(154),_=i(384);const w=e=>y.RI&&!0===e?.privacy.cookies_enabled;function x(e){return!!(0,_.dV)().o.MO&&w(e)&&!0===e?.session_trace.enabled}var k=i(389),S=i(699);class A extends v.W{constructor(e,t){super(e.agentIdentifier,t),this.agentRef=e,this.abortHandler=void 0,this.featAggregate=void 0,this.onAggregateImported=void 0,this.deferred=Promise.resolve(),!1===e.init[this.featureName].autoStart?this.deferred=new Promise(((t,r)=>{this.ee.on("manual-start-all",(0,k.J)((()=>{(0,h.Ak)(e.agentIdentifier,this.featureName),t()})))})):(0,h.Ak)(e.agentIdentifier,t)}importAggregator(e,t,r={}){if(this.featAggregate)return;let n;this.onAggregateImported=new Promise((e=>{n=e}));const a=async()=>{let a;await this.deferred;try{if(w(e.init)){const{setupAgentSession:t}=await i.e(296).then(i.bind(i,305));a=t(e)}}catch(e){(0,l.R)(20,e),this.ee.emit("internal-error",[e]),(0,o.p)(S.qh,[e],void 0,this.featureName,this.ee)}try{if(!this.#t(this.featureName,a,e.init))return(0,h.Ze)(this.agentIdentifier,this.featureName),void n(!1);const{Aggregate:i}=await t();this.featAggregate=new i(e,r),e.runtime.harvester.initializedAggregates.push(this.featAggregate),n(!0)}catch(e){(0,l.R)(34,e),this.abortHandler?.(),(0,h.Ze)(this.agentIdentifier,this.featureName,!0),n(!1),this.ee&&this.ee.abort()}};y.RI?(0,b.GG)((()=>a()),!0):a()}#t(e,t,r){if(this.blocked)return!1;switch(e){case n.K7.sessionReplay:return x(r)&&!!t;case n.K7.sessionTrace:return!!t;default:return!0}}}var R=i(630),T=i(614);class E extends A{static featureName=R.T;constructor(e){var t;super(e,R.T),this.setupInspectionEvents(e.agentIdentifier),t=e,p(u.Fw,(function(e,r){"string"==typeof e&&("/"!==e.charAt(0)&&(e="/"+e),t.runtime.customTransaction=(r||"http://custom.transaction")+e,(0,o.p)(u.Pl+u.Fw,[(0,c.t)()],void 0,void 0,t.ee))}),t),this.ee.on("api-send-rum",((e,t)=>(0,o.p)("send-rum",[e,t],void 0,this.featureName,this.ee))),this.importAggregator(e,(()=>i.e(296).then(i.bind(i,108))))}setupInspectionEvents(e){const t=(t,r)=>{t&&(0,d.W)({agentIdentifier:e,timeStamp:t.timeStamp,loaded:"complete"===t.target.readyState,type:"window",name:r,data:t.target.location+""})};(0,b.sB)((e=>{t(e,"DOMContentLoaded")})),(0,b.GG)((e=>{t(e,"load")})),(0,b.Qr)((e=>{t(e,"navigate")})),this.ee.on(T.tS.UPDATE,((t,r)=>{(0,d.W)({agentIdentifier:e,type:"lifecycle",name:"session",data:r})}))}}var N=i(843),I=i(878),j=i(782);class O extends A{static featureName=j.T;constructor(e){super(e,j.T),y.RI&&((0,N.u)((()=>(0,o.p)("docHidden",[(0,c.t)()],void 0,j.T,this.ee)),!0),(0,I.sp)("pagehide",(()=>(0,o.p)("winPagehide",[(0,c.t)()],void 0,j.T,this.ee))),this.importAggregator(e,(()=>i.e(296).then(i.bind(i,350)))))}}class P extends A{static featureName=g.TZ;constructor(e){super(e,g.TZ),y.RI&&document.addEventListener("securitypolicyviolation",(e=>{(0,o.p)(g.xV,["Generic/CSPViolation/Detected"],void 0,this.featureName,this.ee)})),this.importAggregator(e,(()=>i.e(296).then(i.bind(i,373))))}}new class extends r{constructor(e){var t;(super(),y.gm)?(this.features={},(0,_.bQ)(this.agentIdentifier,this),this.desiredFeatures=new Set(e.features||[]),this.desiredFeatures.add(E),this.runSoftNavOverSpa=[...this.desiredFeatures].some((e=>e.featureName===n.K7.softNav)),(0,s.j)(this,e,e.loaderType||"agent"),t=this,p(u.cD,(function(e,r,n=!1){if("string"==typeof e){if(["string","number","boolean"].includes(typeof r)||null===r)return m(t,e,r,u.cD,n);(0,l.R)(40,typeof r)}else(0,l.R)(39,typeof e)}),t),function(e){p(u.Dl,(function(t){if("string"==typeof t||null===t)return m(e,"enduser.id",t,u.Dl,!0);(0,l.R)(41,typeof t)}),e)}(this),function(e){p(u.nb,(function(t){if("string"==typeof t||null===t)return m(e,"application.version",t,u.nb,!1);(0,l.R)(42,typeof t)}),e)}(this),function(e){p(u.d3,(function(){e.ee.emit("manual-start-all")}),e)}(this),this.run()):(0,l.R)(21)}get config(){return{info:this.info,init:this.init,loader_config:this.loader_config,runtime:this.runtime}}get api(){return this}run(){try{const e=function(e){const t={};return a.forEach((r=>{t[r]=!!e[r]?.enabled})),t}(this.init),t=[...this.desiredFeatures];t.sort(((e,t)=>n.P3[e.featureName]-n.P3[t.featureName])),t.forEach((t=>{if(!e[t.featureName]&&t.featureName!==n.K7.pageViewEvent)return;if(this.runSoftNavOverSpa&&t.featureName===n.K7.spa)return;if(!this.runSoftNavOverSpa&&t.featureName===n.K7.softNav)return;const r=function(e){switch(e){case n.K7.ajax:return[n.K7.jserrors];case n.K7.sessionTrace:return[n.K7.ajax,n.K7.pageViewEvent];case n.K7.sessionReplay:return[n.K7.sessionTrace];case n.K7.pageViewTiming:return[n.K7.pageViewEvent];default:return[]}}(t.featureName).filter((e=>!(e in this.features)));r.length>0&&(0,l.R)(36,{targetFeature:t.featureName,missingDependencies:r}),this.features[t.featureName]=new t(this)}))}catch(e){(0,l.R)(22,e);for(const e in this.features)this.features[e].abortHandler?.();const t=(0,_.Zm)();delete t.initializedAgents[this.agentIdentifier]?.features,delete this.sharedAggregator;return t.ee.get(this.agentIdentifier).abort(),!1}}}({features:[E,O,P],loaderType:"lite"})})()})();</script>        <script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start': new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0], j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src= 'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f); })(window,document,'script','dataLayer','GTM-M586FKF');</script>

<style>.body-wrapper { overflow: visible !important } </style>

<script>
  (function() {
    const pathname = window.location.pathname;

    if (pathname.includes('https://community.veeam.com/onboarding-for-veeam-data-platform-163')) {
      const style = document.createElement('style');
      style.innerHTML = `
        .widget--related-topics,
        .breadcrumb-container {
          display: none !important;
        }
      `;
      document.head.appendChild(style);
    }
  })();
</script>
    
        

<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta name="format-detection" content="telephone=no">
<meta name="HandheldFriendly" content="true" />
<meta http-equiv="X-UA-Compatible" content="ie=edge">

<link rel="shortcut icon" type="image/png" href="https://uploads-eu-west-1.insided.com/veeam-en/attachment/9fcbadba-fa71-42f3-a070-1df5e268329c.png" />
<title>Featured YARA rule: Top 10 Ransomware Threats | Veeam Community Resource Hub</title>
<meta name="description" content="Now that V12.1 is available, I wanted to share with you a featured YARA rule set that can give you on-demand scanning for some top ransomware threats. A...">

<meta property="og:title" content="Featured YARA rule: Top 10 Ransomware Threats | Veeam Community Resource Hub"/>
<meta property="og:type" content="article" />
<meta property="og:url" content="https://community.veeam.com/yara-and-script-library-67/featured-yara-rule-top-10-ransomware-threats-6267"/>
<meta property="og:description" content="Now that V12.1 is available, I wanted to share with you a featured YARA rule set that can give you on-demand scanning for some top ransomware threats. Attached to this post is a file named: Top10RW_YARArules.zip. In this file are YARA rules for some common ransomware threats that have been seen rece..." />
<meta property="og:image" content="https://uploads-eu-west-1.insided.com/veeam-en/attachment/dc66dfff-0a30-4692-89d3-ae8de9b951f9_thumb.png"/>
<meta property="og:image:secure_url" content="https://uploads-eu-west-1.insided.com/veeam-en/attachment/dc66dfff-0a30-4692-89d3-ae8de9b951f9_thumb.png"/>


    <link rel="canonical" href="https://community.veeam.com/yara-and-script-library-67/featured-yara-rule-top-10-ransomware-threats-6267" />

        
<style id="css-variables">@font-face{ font-family:Roboto; src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bold/Roboto-Bold-webfont.eot); src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bold/Roboto-Bold-webfont.eot#iefix) format("embedded-opentype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bold/Roboto-Bold-webfont.woff) format("woff"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bold/Roboto-Bold-webfont.ttf) format("truetype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bold/Roboto-Bold-webfont.svg#2dumbregular) format("svg"); font-style:normal; font-weight:700 } @font-face{ font-family:Roboto; src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bolditalic/Roboto-BoldItalic-webfont.eot); src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bolditalic/Roboto-BoldItalic-webfont.eot#iefix) format("embedded-opentype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bolditalic/Roboto-BoldItalic-webfont.woff) format("woff"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bolditalic/Roboto-BoldItalic-webfont.ttf) format("truetype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bolditalic/Roboto-BoldItalic-webfont.svg#2dumbregular) format("svg"); font-style:italic; font-weight:700 } @font-face{ font-family:Roboto; src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/fonts/roboto/italic/Roboto-Italic-webfont.eot); src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/fonts/roboto/italic/Roboto-Italic-webfont.eot#iefix) format("embedded-opentype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/fonts/roboto/italic/Roboto-Italic-webfont.woff) format("woff"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/fonts/roboto/italic/Roboto-Italic-webfont.ttf) format("truetype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/fonts/roboto/italic/Roboto-Italic-webfont.svg#2dumbregular) format("svg"); font-style:italic; font-weight:normal } @font-face{ font-family:Roboto; src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/light/Roboto-Light-webfont.eot); src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/light/Roboto-Light-webfont.eot#iefix) format("embedded-opentype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/light/Roboto-Light-webfont.woff) format("woff"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/light/Roboto-Light-webfont.ttf) format("truetype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/light/Roboto-Light-webfont.svg#2dumbregular) format("svg"); font-style:normal; font-weight:300 } @font-face{ font-family:Roboto; src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/medium/Roboto-Medium-webfont.eot); src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/medium/Roboto-Medium-webfont.eot#iefix) format("embedded-opentype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/medium/Roboto-Medium-webfont.woff) format("woff"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/medium/Roboto-Medium-webfont.ttf) format("truetype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/medium/Roboto-Medium-webfont.svg#2dumbregular) format("svg"); font-style:normal; font-weight:500 } @font-face{ font-family:Roboto; src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/mediumitalic/Roboto-MediumItalic-webfont.eot); src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/mediumitalic/Roboto-MediumItalic-webfont.eot#iefix) format("embedded-opentype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/mediumitalic/Roboto-MediumItalic-webfont.woff) format("woff"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/mediumitalic/Roboto-MediumItalic-webfont.ttf) format("truetype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/mediumitalic/Roboto-MediumItalic-webfont.svg#2dumbregular) format("svg"); font-style:italic; font-weight:500 } @font-face{ font-family:Roboto; src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/regular/Roboto-Regular-webfont.eot); src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/regular/Roboto-Regular-webfont.eot#iefix) format("embedded-opentype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/regular/Roboto-Regular-webfont.woff) format("woff"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/regular/Roboto-Regular-webfont.ttf) format("truetype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/regular/Roboto-Regular-webfont.svg#2dumbregular) format("svg"); font-style:normal; font-weight:normal } html {--borderradius-base: 4px;--config--main-border-base-color: #fffbfbff;--config--main-button-base-font-color: #1a1a1a;--config--main-button-base-font-family: ESBuild,'Guardian TextSans Cy', 'Guardian TextSans', Tahoma, sans-serif;--config--main-button-base-font-weight: 600;--config--main-button-base-radius: 3px;--config--main-button-base-texttransform: uppercase;--config--main-color-alert: #ba0200ff;--config--main-color-brand: #00d15fff;--config--main-color-brand-secondary: #00d15fff;--config--main-color-contrast: #2aaae1;--config--main-color-day: #f0f2f6;--config--main-color-day-dark: #ededed;--config--main-color-day-light: #fff;--config--main-color-disabled: #999999ff;--config--main-color-dusk: #a7aeb5;--config--main-color-dusk-dark: #616a73;--config--main-color-dusk-light: #d5d7db;--config--main-color-highlighted: #B0DFF3;--config--main-color-info: #ffffffff;--config--main-color-night: #000000ff;--config--main-color-night-inverted: #f5f5f5;--config--main-color-night-light: #2b2b2b;--config--main-color-success: #00d15fff;--config--main-font-base-lineheight: 1.5;--config--main-font-base-stack: ESBuild,'Guardian TextSans Cy', 'Guardian TextSans', Tahoma, sans-serif;--config--main-font-base-style: normal;--config--main-font-base-weight: normal;--config--main-font-secondary: ESBuild,'Guardian TextSans Cy', 'Guardian TextSans', Tahoma, sans-serif;--config--main-fonts: @font-face{ font-family:Roboto; src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bold/Roboto-Bold-webfont.eot); src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bold/Roboto-Bold-webfont.eot#iefix) format("embedded-opentype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bold/Roboto-Bold-webfont.woff) format("woff"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bold/Roboto-Bold-webfont.ttf) format("truetype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bold/Roboto-Bold-webfont.svg#2dumbregular) format("svg"); font-style:normal; font-weight:700 } @font-face{ font-family:Roboto; src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bolditalic/Roboto-BoldItalic-webfont.eot); src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bolditalic/Roboto-BoldItalic-webfont.eot#iefix) format("embedded-opentype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bolditalic/Roboto-BoldItalic-webfont.woff) format("woff"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bolditalic/Roboto-BoldItalic-webfont.ttf) format("truetype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/bolditalic/Roboto-BoldItalic-webfont.svg#2dumbregular) format("svg"); font-style:italic; font-weight:700 } @font-face{ font-family:Roboto; src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/fonts/roboto/italic/Roboto-Italic-webfont.eot); src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/fonts/roboto/italic/Roboto-Italic-webfont.eot#iefix) format("embedded-opentype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/fonts/roboto/italic/Roboto-Italic-webfont.woff) format("woff"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/fonts/roboto/italic/Roboto-Italic-webfont.ttf) format("truetype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/fonts/roboto/italic/Roboto-Italic-webfont.svg#2dumbregular) format("svg"); font-style:italic; font-weight:normal } @font-face{ font-family:Roboto; src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/light/Roboto-Light-webfont.eot); src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/light/Roboto-Light-webfont.eot#iefix) format("embedded-opentype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/light/Roboto-Light-webfont.woff) format("woff"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/light/Roboto-Light-webfont.ttf) format("truetype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/light/Roboto-Light-webfont.svg#2dumbregular) format("svg"); font-style:normal; font-weight:300 } @font-face{ font-family:Roboto; src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/medium/Roboto-Medium-webfont.eot); src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/medium/Roboto-Medium-webfont.eot#iefix) format("embedded-opentype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/medium/Roboto-Medium-webfont.woff) format("woff"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/medium/Roboto-Medium-webfont.ttf) format("truetype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/medium/Roboto-Medium-webfont.svg#2dumbregular) format("svg"); font-style:normal; font-weight:500 } @font-face{ font-family:Roboto; src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/mediumitalic/Roboto-MediumItalic-webfont.eot); src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/mediumitalic/Roboto-MediumItalic-webfont.eot#iefix) format("embedded-opentype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/mediumitalic/Roboto-MediumItalic-webfont.woff) format("woff"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/mediumitalic/Roboto-MediumItalic-webfont.ttf) format("truetype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/mediumitalic/Roboto-MediumItalic-webfont.svg#2dumbregular) format("svg"); font-style:italic; font-weight:500 } @font-face{ font-family:Roboto; src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/regular/Roboto-Regular-webfont.eot); src:url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/regular/Roboto-Regular-webfont.eot#iefix) format("embedded-opentype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/regular/Roboto-Regular-webfont.woff) format("woff"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/regular/Roboto-Regular-webfont.ttf) format("truetype"),url(https://d2cn40jarzxub5.cloudfront.net/_fonts/fonts/roboto/regular/Roboto-Regular-webfont.svg#2dumbregular) format("svg"); font-style:normal; font-weight:normal };--config--main-header-font-weight: 600;--config-anchor-base-color: #00d15fff;--config-anchor-base-hover-color: #00d15fff;--config-avatar-notification-background-color: #00d15fff;--config-body-background-color: #ffffffff;--config-body-wrapper-background-color: transparent;--config-body-wrapper-box-shadow: 0 0 0 transparent;--config-body-wrapper-max-width: 100%;--config-button-cancel-active-background-color: #9f0200;--config-button-cancel-active-border-color: #9f0200;--config-button-cancel-active-color: #fff;--config-button-cancel-background-color: transparent;--config-button-cancel-border-color: #ba0200;--config-button-cancel-border-radius: 6px;--config-button-cancel-border-width: 2px;--config-button-cancel-box-shadow: 0 0 0 transparent;--config-button-cancel-color: #ba0200;--config-button-cancel-hover-background-color: #ba0200;--config-button-cancel-hover-border-color: #ba0200;--config-button-cancel-hover-color: #fff;--config-button-cta-active-background-color: #283e8e;--config-button-cta-active-border-color: #283e8e;--config-button-cta-active-border-width: 2px;--config-button-cta-active-box-shadow: 0 0 0 transparent;--config-button-cta-active-color: #ffffff;--config-button-cta-background-color: #3700FF;--config-button-cta-border-color: #3700FF;--config-button-cta-border-radius: 6px;--config-button-cta-border-width: 2px;--config-button-cta-box-shadow: 0 0 0 transparent;--config-button-cta-color: #ffffff;--config-button-cta-focus-background-color: #3500f5ff;--config-button-cta-focus-border-color: #00b753ff;--config-button-cta-focus-border-width: 2px;--config-button-cta-focus-color: #ffffff;--config-button-cta-hover-background-color: #283e8e;--config-button-cta-hover-border-color: #283e8e;--config-button-cta-hover-border-width: 2px;--config-button-cta-hover-box-shadow: 0 0 0 transparent;--config-button-cta-hover-color: #ffffff;--config-button-cta-spinner-color: #fff;--config-button-cta-spinner-hover-color: #fff;--config-button-secondary-active-background-color: #283e8e;--config-button-secondary-active-border-color: #283e8e;--config-button-secondary-active-border-width: 2px;--config-button-secondary-active-box-shadow: 0 0 0 transparent;--config-button-secondary-active-color: #ffffff;--config-button-secondary-background-color: #ffffff00;--config-button-secondary-border-color: #3700ff;--config-button-secondary-border-radius: 6px;--config-button-secondary-border-width: 2px;--config-button-secondary-box-shadow: 0 0 0 transparent;--config-button-secondary-color: #3700ff;--config-button-secondary-focus-background-color: #00b753ff;--config-button-secondary-focus-border-color: #00b753ff;--config-button-secondary-focus-border-width: 2px;--config-button-secondary-focus-color: #3700ff;--config-button-secondary-hover-background-color: #283e8e;--config-button-secondary-hover-border-color: #283e8e;--config-button-secondary-hover-border-width: 2px;--config-button-secondary-hover-box-shadow: 0 0 0 transparent;--config-button-secondary-hover-color: #ffffff;--config-button-secondary-spinner-color: #fff;--config-button-secondary-spinner-hover-color: #fff;--config-button-toggle-active-background-color: #acacac;--config-button-toggle-active-border-color: #acacac;--config-button-toggle-active-color: #fff;--config-button-toggle-background-color: transparent;--config-button-toggle-border-color: #232323;--config-button-toggle-border-radius: 6px;--config-button-toggle-border-width: 2px;--config-button-toggle-box-shadow: 0 0 0 transparent;--config-button-toggle-color: #232323;--config-button-toggle-filled-background-color: #00d15fff;--config-button-toggle-filled-color: #fff;--config-button-toggle-filled-pseudo-color: #fff;--config-button-toggle-filled-spinner-color: #fff;--config-button-toggle-focus-border-color: #00b753ff;--config-button-toggle-hover-background-color: #f4f4f4;--config-button-toggle-hover-border-color: #232323;--config-button-toggle-hover-color: #232323;--config-button-toggle-on-active-background-color: #acacac;--config-button-toggle-on-active-border-color: #acacac;--config-button-toggle-on-active-color: #ffffff;--config-button-toggle-on-background-color: #acacac;--config-button-toggle-on-border-color: #acacac;--config-button-toggle-on-border-radius: 6px;--config-button-toggle-on-border-width: 2px;--config-button-toggle-on-box-shadow: 0 0 0 transparent;--config-button-toggle-on-color: #fff;--config-button-toggle-on-hover-background-color: #f4f4f4;--config-button-toggle-on-hover-border-color: #232323;--config-button-toggle-on-hover-color: #232323;--config-button-toggle-outline-background-color: #00d15fff;--config-button-toggle-outline-color: #00d15fff;--config-button-toggle-outline-pseudo-color: #00d15fff;--config-button-toggle-outline-spinner-color: #00d15fff;--config-content-type-article-color: #fff;--config-cookie-modal-background-color: rgba(60,60,60,.9);--config-cookie-modal-color: #fff;--config-create-topic-type-icon-color: #000000ff;--config-cta-close-button-color: #a7aeb5;--config-cta-icon-background-color: #00d15fff;--config-cta-icon-check: #fff;--config-editor-comment-toolbar-background-color: #fff;--config-editor-comment-toolbar-button-color: #000000ff;--config-editor-comment-toolbar-button-hover-color: #00d15fff;--config-footer-background-color: #000000ff;--config-footer-color: #fff;--config-header-color: #000000ff;--config-header-color-inverted: #f5f5f5;--config-hero-background-position: top left;--config-hero-color: #000000ff;--config-hero-font-weight: bold;--config-hero-stats-background-color: #fff;--config-hero-stats-counter-font-weight: bold;--config-hero-text-shadow: none;--config-input-focus-color: #00d15fff;--config-link-base-color: #000000ff;--config-link-base-hover-color: #00d15fff;--config-link-hover-decoration: none;--config-main-navigation-background-color: #fff;--config-main-navigation-border-bottom-color: #00d15f;--config-main-navigation-border-top-color: #00d15f;--config-main-navigation-dropdown-background-color: #fff;--config-main-navigation-dropdown-color: #2b3346;--config-main-navigation-dropdown-font-weight: normal;--config-main-navigation-nav-color: rgb(255,255,255);--config-main-navigation-nav-font-weight: normal;--config-main-navigation-nav-link-color: #3700ff;--config-main-navigation-search-placeholder-color: #cdcdcdff;--config-mention-selector-hover-selected-color: #fff;--config-meta-link-font-weight: normal;--config-meta-link-hover-color: #00d15fff;--config-meta-text-color: #999999ff;--config-notification-widget-background-color: #00d15fff;--config-notification-widget-color: #232323ff;--config-pagination-active-page-color: #00d15fff;--config-paging-item-hover-color: #00d15fff;--config-pill-color: #fff;--config-powered-by-insided-display: visible;--config-profile-user-statistics-background-color: #fff;--config-sharpen-fonts: true;--config-sidebar-widget-color: #000000ff;--config-sidebar-widget-font-family: ESBuild,'Guardian TextSans Cy', 'Guardian TextSans', Tahoma, sans-serif;--config-sidebar-widget-font-weight: 600;--config-ssi-header-height: auto;--config-ssi-header-mobile-height: auto;--config-subcategory-hero-color: #000000ff;--config-tag-modify-link-color: #00d15fff;--config-tag-pill-background-color: #f8f8f8;--config-tag-pill-hover-background-color: #8cffebff;--config-tag-pill-hover-border-color: #00d15fff;--config-tag-pill-hover-color: #00d15fff;--config-thread-list-best-answer-background-color: #00d15f0d;--config-thread-list-best-answer-border-color: #00d15fff;--config-thread-list-mod-break-background: #00d15f0d;--config-thread-list-mod-break-border-color: #00d15fff;--config-thread-list-sticky-topic-background: #00d15ff2;--config-thread-list-sticky-topic-border-color: #00d15fff;--config-thread-list-sticky-topic-flag-color: #00d15fff;--config-thread-list-topic-button-subscribe-border-width: 1px;--config-thread-list-topic-title-font-weight: bold;--config-thread-pill-answer-background-color: #00d15fff;--config-thread-pill-author-background-color: #00d15fff;--config-thread-pill-author-color: #fff;--config-thread-pill-question-background-color: #f7941dff;--config-thread-pill-question-color: #fff;--config-thread-pill-sticky-background-color: #00d15fff;--config-thread-pill-sticky-color: #fff;--config-topic-page-answered-field-icon-color: #00d15fff;--config-topic-page-answered-field-link-color: #00d15fff;--config-topic-page-header-font-weight: 600;--config-topic-page-post-actions-active: #00d15fff;--config-topic-page-post-actions-icon-color: #a7aeb5;--config-topic-page-quote-border-color: #fffbfbff;--config-topic-question-color: #f7941dff;--config-widget-box-shadow: 0 2px 4px 0 rgba(0,0,0,0.08);--config-widget-cta-background-color: #070808ff;--config-widget-cta-color: #000000ff;--config-widget-tabs-font-weight: normal;--config-widget-tabs-forum-list-header-color: #000000ff;--config-widget-tabs-forum-list-header-hover-color: #00d15fff;--config-card-border-radius: 4px;--config-card-border-width: 1px;--config-card-background-color: #ffffff;--config-card-title-color: #232323;--config-card-text-color: #232323ff;--config-card-border-color: #cdcdcd;--config-card-hover-background-color: #ffffff;--config-card-hover-title-color: #232323;--config-card-hover-text-color: #232323ff;--config-card-hover-border-color: #ffffffff;--config-card-hover-shadow: 0 5px 20px 0 rgba(0, 0, 0, 0.08);--config-card-active-background-color: #ffffff;--config-card-active-title-color: #232323;--config-card-active-text-color: #232323;--config-sidebar-background-color: transparent;--config-sidebar-border-color: transparent;--config-sidebar-border-radius: 3px;--config-sidebar-border-width: 1px;--config-sidebar-shadow: 0 0 0 transparent;--config-list-views-use-card-theme: 0;--config-list-views-card-border-width: 1px;--config-list-views-card-border-radius: 5px;--config-list-views-card-default-background-color: #ffffff;--config-list-views-card-default-title-color: #000000ff;--config-list-views-card-default-text-color: #000000ff;--config-list-views-card-default-border-color: #fffbfbff;--config-list-views-card-hover-background-color: #ffffff;--config-list-views-card-hover-title-color: #000000ff;--config-list-views-card-hover-text-color: #000000ff;--config-list-views-card-hover-border-color: #fffbfbff;--config-list-views-card-click-background-color: #ffffff;--config-list-views-card-click-title-color: #000000ff;--config-list-views-card-click-text-color: #000000ff;--config-list-views-card-click-border-color: #fffbfbff;--config-sidebar-widget-username-color: #232323ff;--config-username-hover-color: #00b336ff;--config-username-hover-decoration: none;--config-content-type-survey-background-color: #322c75;--config-content-type-survey-color: #fff;--config-checkbox-checked-color: #322c75;--config-content-type-article-background-color: #322c75;--config-main-navigation-dropdown-hover-color: #322c75;--config-meta-icon-color: #a7aeb5;--config-tag-pill-border-color: #e3e4ec;--config-tag-pill-color: #2b3346;--config-username-color: #322c75;--config-widget-tabs-active-border-color: #322c75;--config-widgets-action-link-color: #322c75;--config-button-cta-advanced: 1;--config-button-secondary-advanced: 1;--config-button-border-width: 2px;--config-button-border-radius: 6px;--config-button-cta-hover-border-radius: 6px;--config-button-cta-active-border-radius: 6px;--config-button-secondary-hover-border-radius: 6px;--config-button-secondary-active-border-radius: 6px;--config-button-toggle-hover-border-radius: 6px;--config-button-toggle-active-border-radius: 6px;--config-button-toggle-on-hover-border-radius: 6px;--config-button-toggle-on-active-border-radius: 6px;--config-button-cancel-hover-border-radius: 6px;--config-button-cancel-active-border-radius: 6px;--config-button-toggle-hover-border-width: 2px;--config-button-toggle-active-border-width: 2px;--config-button-toggle-on-hover-border-width: 2px;--config-button-toggle-on-active-border-width: 2px;--config-button-cancel-hover-border-width: 2px;--config-button-cancel-active-border-width: 2px;--config--favicon-url: https://uploads-eu-west-1.insided.com/veeam-en/attachment/9fcbadba-fa71-42f3-a070-1df5e268329c.png;}</style>

<link href="https://d3odp2r1osuwn0.cloudfront.net/2025-09-30-13-23-03-037e73449a/dist/css/preact-app.css" id='main-css' rel="stylesheet" type="text/css" />

<script nonce="">if (!(window.CSS && CSS.supports('color', 'var(--fake-var)'))) {
    document.head.removeChild(document.getElementById('main-css'))
    document.write('<link href="/destination.css" rel="stylesheet" type="text/css"><\x2flink>');
}</script>



    <style> /*
Before updates -- go to GIT:
MKTO\static\src\lp\projects\2020\veeam-en-community.insided.com
pull previous  versions of scss, update it -- push to git and pull new css to veeam-en-community
*/
/* ************************************************* GM - s  ************************************************* */

/* Media queries */
/* Placeholders */
@import url(https://psr.veeam.com/global/css/GuardianSans.min.css);
@import url(https://psr.veeam.com/global/css/font-awesome.min.css);

@font-face {
  font-family: ESBuild;
  src: url(https://css.veeam.com/fonts/es-build-family/web/ES-Build.woff2) format("woff2");
  font-weight: 400 700;
}

/* Sizes */
/* Colors */
/* @mixins */
/* font-size */
.logo-insided {
  display: none !important;
}

body {
  font: normal 16px/1.5 ESBuild, Tahoma, "Trebuchet MS", sans-serif;
  min-width: 310px;
}

h1,
h2,
h3,
h4,
h5,
h6 {
  font-family: ESBuild, Tahoma, "Trebuchet MS", sans-serif;
  font-weight: 500;
  line-height: 1.3;
}

h2,
h3 {
  font-size: 24px !important;
  line-height: 32px;
  padding-bottom: 0;
}

h3 {
  font-size: 24px;
  line-height: 32px;
  padding-bottom: 0;
  margin-bottom: 12px;
}

h4,
h5,
h6 {
  font-size: 24px;
  line-height: 32px;
  margin-bottom: 8px;
}

li {
  margin-bottom: 8px;
}

.body-wrapper {
  overflow: hidden;
}

a:active {
  color: #3700FF;
}

a:hover {
  color: #3700FF;
}

a,
.btn {
  outline: none !important;
  /*outline-color: #f1f1f1 !important;*/
}

.instant-search-wrapper .instant-search__filters-list .instant-search__filter-list-pill .instant-search__filter-count {
  height: 21px;
}

.topic-view .topic-view_body .thread-list-block__title .pill,
.instant-search-wrapper .instant-search__filters-list .instant-search__filter-list-pill {
  border-radius: 99999px;
  padding-top: 6px;
}

#modal_report .btn,
.btn,
.btn--cancel,
.btn--cta,
.btn--insided-brand,
.btn--insided-secondary-brand,
.btn--new-topic,
.btn--purple,
.btn--secondary,
.btn--silent,
.btn--toggle,
.btn--toggle-on,
.btn--toggle.is-active,
.btn--toggle.is-follow,
.btn--toggle.preact_voted,
.btn--toggle.thread-meta-item,
.event-header-container .event-header-wrapper .event__attended,
.event-header-container .event-header-wrapper .event__attended:hover,
.event-header-container .event-header-wrapper .event__attending,
.event-header-container .event-header-wrapper .event__attending:hover,
.event-header-container .event-header-wrapper .event__ended,
.event-header-container .event-header-wrapper .event__ended:hover,
.homepage-widget-configurator .homepage-widget-configurator__controls .btn-primary,
.homepage-widget-configurator .widget-configurator__controls .btn-primary,
.offline-community .btn,
.private-register .btn,
.thread--user-liked .thread-meta-item--likes .btn--toggle,
.widget-configurator .homepage-widget-configurator__controls .btn-primary,
.widget-configurator .widget-configurator__controls .btn-primary,
.wysiwyg-editor.wysiwyg-editor-profile__forum_pm .wysiwyg-editor__submit-button,
.wysiwyg-editor .wysiwyg-editor__form-submit,
.wysiwyg-editor .wysiwyg-editor__link--selector .btn,
.wysiwyg-editor .wysiwyg-editor__submit-button {
  box-sizing: border-box;
  padding: 12px 30px 10px;
  text-align: center;
  line-height: 1.5;
  font-style: normal;
  font-weight: 600;
  font-stretch: normal;
  text-decoration: none;
  text-transform: uppercase;
  /*color:#000000;*/
  font-size: 16px;
  border: 0 none;
  outline: 0;
  border-radius: 99999px;
  transition: background .15s ease-in-out;
}

#modal_report .btn:hover,
.btn:hover,
.btn--cancel:hover,
.btn--cta:hover,
.btn--insided-brand:hover,
.btn--insided-secondary-brand:hover,
.btn--new-topic:hover,
.btn--purple:hover,
.btn--secondary:hover,
.btn--silent:hover,
.btn--toggle:hover,
.btn--toggle-on:hover,
.btn--toggle.is-active:hover,
.btn--toggle.is-follow:hover,
.btn--toggle.preact_voted:hover,
.btn--toggle.thread-meta-item:hover,
.event-header-container .event-header-wrapper .event__attended:hover,
.event-header-container .event-header-wrapper .event__attended:hover:hover,
.event-header-container .event-header-wrapper .event__attending:hover,
.event-header-container .event-header-wrapper .event__attending:hover:hover,
.event-header-container .event-header-wrapper .event__ended:hover,
.event-header-container .event-header-wrapper .event__ended:hover:hover,
.homepage-widget-configurator .homepage-widget-configurator__controls .btn-primary:hover,
.homepage-widget-configurator .widget-configurator__controls .btn-primary:hover,
.offline-community .btn:hover,
.private-register .btn:hover,
.thread--user-liked .thread-meta-item--likes .btn--toggle:hover,
.widget-configurator .homepage-widget-configurator__controls .btn-primary:hover,
.widget-configurator .widget-configurator__controls .btn-primary:hover,
.wysiwyg-editor.wysiwyg-editor-profile__forum_pm .wysiwyg-editor__submit-button:hover,
.wysiwyg-editor .wysiwyg-editor__form-submit:hover,
.wysiwyg-editor .wysiwyg-editor__link--selector .btn:hover,
.wysiwyg-editor .wysiwyg-editor__submit-button:hover {
  text-decoration: none;
}

.event-header-container .event-header-wrapper .event__attended,
.event-header-container .event-header-wrapper .event__attended:hover,
.event-header-container .event-header-wrapper .event__ended,
.event-header-container .event-header-wrapper .event__ended:hover {
  background: #cdcdcd;
  color: #ffffff;
}

.box__pad {
  /*padding-left: 0;
  padding-right: 0;*/
  text-align: left;
}

.box--note {
  text-align: left;
}

.box--profile-fields .profile-fields {
  width: auto;
}

.box--profile-fields .profile-fields .table__cell {
  padding-right: 20px;
}

.box--profile-fields .profile-fields .table__cell.box-title {
  padding-bottom: 15px;
}

/* hero banner left aligned - s */
.hero-subforum-title {
  font-size: 60px;
  line-height: 68px;
}

.hero-subforum-title+.hero-subforum-description {
  margin-top: 16px;
  font-size: 28px;
  line-height: 36px;
}

.searchbar-in-hero,
.brand-hero-title+.hero-search {
  margin-top: 32px;
}

.custom-hero-banner {
  /* background-image: url(https://go.veeam.com/rs/870-LBG-312/images/header_veeam_en_community_general_2x.png) !important; */
}

@media screen and (max-width: 480px) {
  .custom-hero-banner {
    background-image: none !important;
  }
}

.custom-hero-banner,
.forum-featured-image {
  background-color: #333639 !important;
  background-size: cover;
  background-repeat: no-repeat;
  background-position: 44% 0%;
  height: auto;
  min-height: 254px;
  padding-top: 60px;
  padding-bottom: 110px;
  text-align: left;
  -webkit-box-sizing: border-box;
  -moz-box-sizing: border-box;
  box-sizing: border-box;
}

@media screen and (max-width: 480px) {

  .custom-hero-banner,
  .forum-featured-image {
    padding: 30px 10px;
    text-align: center;
  }
}

.custom-hero-banner .brand-hero-title,
.forum-featured-image .brand-hero-title {
  font-size: 52px;
  line-height: 60px;
  text-align: left;
  max-width: 60%;
}

@media screen and (max-width: 768px) {

  .custom-hero-banner .brand-hero-title,
  .forum-featured-image .brand-hero-title {
    font-size: 45px;
    max-width: 90%;
  }
}

@media screen and (max-width: 480px) {

  .custom-hero-banner .brand-hero-title,
  .forum-featured-image .brand-hero-title {
    font-size: 40px;
    line-height: 1.3;
    max-width: 100%;
    text-align: center;
  }
}

.custom-hero-banner .hero-search,
.forum-featured-image .hero-search {
  margin-left: 0;
  margin-right: 0;
}

/* hero banner left aligned - e */
/* **************************************************** NEW MENU and LOGO - s ************************************************* */
.main-menu-trigger {
  font-size: 16px;
}

@media screen and (max-width: 1024px) {
  .main-menu-trigger {
    /*background: $color-teal;*/
    background: #fff;
    color: #004550;
    border-top: 1px solid #004550;
    border-bottom: 1px solid #004550;
    padding-top: 14px !important;
    padding-bottom: 14px !important;
    /*color: $color-text-main;*/
  }
}

@media screen and (min-width: 769px) {
  .main-navigation--nav-buttons-wrapper>ul {
    flex-direction: row-reverse;
  }
}

.main-navigation--nav-buttons-wrapper .link:hover {
  color: #fff;
}

.header-navigation .header-navigation_logo {
  height: 25px;
}

@media screen and (min-width: 767px) {
  .header-navigation .header-navigation_logo {
    height: 33px;
  }
}

.header-navigation .avatar {
  width: 30px;
  height: 30px;
}

.header-navigation .header-navigation_extendable-search .header-navigation_extendable-search-icon {
  height: 30px;
  width: 30px;
  min-width: 30px;
  padding: 0;
  margin-left: 4px;
  background: transparent;
  border: 0 none;
  line-height: 1;
  color: #fff;
  box-shadow: none;
}

@media screen and (min-width: 1025px) {
  .header-navigation .header-navigation-items_hamburger {
    color: #fff;
  }
}

.header-navigation .header-navigation-items_hamburger .slider-trigger {
  color: #fff;
}

.header-navigation .header-navigation_link {
  color: #232323;
}

@media screen and (max-width: 1024px) {
  .header-navigation .header-navigation_link {
    color: #232323;
    border-bottom: 1px solid;
  }

  .header-navigation .header-navigation_link:hover {
    color: #00b336;
  }
}

.header-navigation .main-navigation--nav-buttons-wrapper .btn--secondary {
  background: #00d15f;
  color: #fff;
  padding-top: 15px;
  padding-bottom: 15px;
  box-shadow: inset 0 0 0 -1px #fff, 0 0 0 transparent;
  height: auto;
}

@media screen and (max-width: 767px) {
  .header-navigation .main-navigation--nav-buttons-wrapper .btn--secondary {
    padding-top: 13px;
    padding-bottom: 13px;
    height: auto;
    margin-top: 5px;
  }
}

.header-navigation .main-navigation--nav-buttons-wrapper .btn--secondary:hover {
  color: #fff;
  background: #009277;
}

.header-navigation .main-navigation--nav-buttons-wrapper .btn--secondary:active {
  color: #fff;
  background: #009277;
}

.header-navigation .main-navigation--nav-buttons-wrapper .btn--secondary .header-login-button:hover {
  color: #fff;
}

.header-navigation .main-navigation--nav-buttons-wrapper .btn {
  line-height: 1;
}

@media screen and (min-width: 768px) {
  .header-navigation .main-navigation--nav-buttons-wrapper .btn {
    height: auto;
    margin-left: 24px;
  }
}

.header-navigation .main-navigation--nav-buttons-wrapper .btn.qa-menu-create-topic .header-navigation-button-icon,
.header-navigation .main-navigation--nav-buttons-wrapper .btn.qa-menu-create-topic .header-navigation-button-icon svg {
  display: none !important;
}

@media screen and (min-width: 768px) {
  .header-navigation .main-navigation--nav-buttons-wrapper .btn.qa-menu-create-topic {
    box-sizing: border-box;
    padding: 12px 24px;
    text-align: center;
    line-height: 1.5;
    font-style: normal;
    font-weight: 600;
    font-stretch: normal;
    text-decoration: none;
    text-transform: uppercase;
    /*color:#fff;*/
    font-size: 16px;
    border: 0 none;
    outline: 0;
    border-radius: 6px;
    transition: background .15s ease-in-out;
  }

  .header-navigation .main-navigation--nav-buttons-wrapper .btn.qa-menu-create-topic:hover {
    text-decoration: none;
    padding: 12px 24px;
  }

  .header-navigation .main-navigation--nav-buttons-wrapper .btn.qa-menu-create-topic,
  .header-navigation .main-navigation--nav-buttons-wrapper .btn.qa-menu-create-topic:hover,
  .header-navigation .main-navigation--nav-buttons-wrapper .btn.qa-menu-create-topic:active {
    background-image: url("https://mkto.veeam.com/lp/projects/2020/veeam-en-community.insided.com/img/icon_pen_white.svg");
    background-repeat: no-repeat;
    background-position: 24px 50%;
    padding-left: 49px;
    background-size: 15px 15px;
  }
}

@media screen and (min-width: 768px) {
  .header-navigation .main-navigation--nav-buttons-wrapper .btn .qa-menu-create-topic {
    /*@include g-cta__btn-general-styles();*/
    /*@include g-cta__btn-primary($color-topaz);*/
    /*@include btn-pen();*/
  }

  .header-navigation .main-navigation--nav-buttons-wrapper .btn .qa-menu-create-topic,
  .header-navigation .main-navigation--nav-buttons-wrapper .btn .qa-menu-create-topic:hover,
  .header-navigation .main-navigation--nav-buttons-wrapper .btn .qa-menu-create-topic:active {
    color: #fff;
    padding: 0 0 0 20px;
    background-position: 2px 50%;
  }

  .header-navigation .main-navigation--nav-buttons-wrapper .btn .qa-menu-create-topic .icon--pen {
    display: none !important;
  }
}

/* **************************************************** NEW MENU and LOGO - e ************************************************* */
/* **************************************************** OLD MENU and LOGO - s ************************************************* */
/*

!* main-navigation - s *!
.main-navigation {

    &--wrapper {
        padding-top: 22px;
        padding-bottom: 25px;
        height: auto;

        @include tablet-down() {
            padding-top: 15px;
            padding-bottom: 15px;
        }

        @include mob-down() {
            padding-top: 0;
            padding-bottom: 0;
        }

        .sitewidth.sitewidth--search-wrapper {
            background: $color-teal;
            border: 0 none;
        }

        !* create-topic - s *!

        .menu-create-topic {
            @include g-cta__btn-general-styles();
            @include g-cta__btn-primary($color-topaz);
            @include btn-pen();
            white-space: nowrap;
            margin: 0 0 0 24px;

            !*span {
                color: $color-white !important;
                font-weight: bold;
            }*!


        }
        !* create-topic - e *!
    }

    &--search-wrapper {
        min-width: auto;
    }

    @media screen and (min-width: 768px) {
        &--nav-buttons-wrapper>ul{
            flex-direction: row-reverse;
        }
    }
}
!* main-navigation - e *!


!* edit - s *!
.menu-create-topic .icon--pen {
    display: none !important;
}
!* edit - e *!

!* main-menu - s *!

!* Pre-header - logo mob - s *!
.custom-header {
    @include mob-down() {
        display: block;
        background-color: $color-teal;
        background-repeat: no-repeat;
        background-image: url(https://psr.veeam.com/global/img/logo/veeam_logo_lp_peridot.svg);
        !*background-image: url(https://go.veeam.com/rs/veeam/images/indent.gif);*!
        background-position: 50% 50%;
        height: 25px + 30px;
        background-size: 138.7px 25px;
        padding: 15px 0 15px;
    }
}
!* Pre-header - logo mob - e *!

.main-menu {
    @include mob-up() {
        background: transparent url(https://psr.veeam.com/global/img/logo/veeam_logo_lp_peridot.svg) no-repeat 0% 0%;
        !*background: transparent url(https://go.veeam.com/rs/veeam/images/indent.gif) no-repeat 0% 0%;*!
        height: 25px;
        background-size: 138.7px 25px;
        padding-left: 138.7px + 26px;
        @include flex();
        @include flex__valign(center);
    }
    @include tablet-up() {
        height: 33px;
        background-size: 183px 33px;
        padding-left: 183px + 26px;
    }

    &-trigger {
        color: $color-white;
    }
}

.dropdown {
    &--forums-overview {
        @include tablet-up() {
            left: 183px + 26px;
        }
    }
}
*/
/* main-menu - e */
/* **************************************************** OLD MENU and LOGO - e ************************************************* */
/* search bar - loupe - s */
.search-box__submit {
  /* left: auto;
  right: 0;
  padding: 0;
  color: #fff; */
}

/*search bar style*/
input[type=search].search-box__input {
  color: #fff;
  /*background: $color-teal;*/
  background: rgba(0, 69, 80, 0);
  /* height: 30px; */
}

/* search bar - loupe - e */
.qa-user-profile-box:not(.userprofile-personal .user .flag__image) .avatar {
  width: 48px;
  height: 48px;
}

.qa-user-profile-box:not(.userprofile-personal .user .flag__image) .avatar--S,
.qa-user-profile-box:not(.userprofile-personal .user .flag__image) .avatar--XS {
  width: 24px;
  height: 24px;
}

/* .widget-last-visitors - s */
.Sidebarmodule .widget .Sidebarmodule .widget-title,
.Sidebarmodule .widget__heading {
  margin-top: 48px;
  font-size: 24px;
  line-height: 32px;
}

.Sidebarmodule .widget.box {
  margin-bottom: 48px;
}

.html-editor {
  border-color: #cdcdcd;
}

.html-editor__buttons {
  margin-top: 30px;
}

.widget-title {
  color: #232323;
  font-size: 24px !important;
  line-height: 32px;
  margin-bottom: 0 !important;
  padding-bottom: 24px !important;
}

.widget-last-visitors .avatar--S {
  width: 32px;
  height: 32px;
}

.widget-last-visitors .avatar-variant-0 {
  border: 2px solid #ffffff;
  border-radius: 50%;
}

.widget-last-visitors .avatar-variant-1 {
  border: 2px solid #ffffff;
  border-radius: 50%;
}

.widget-last-visitors .avatar-variant-2 {
  border: 2px solid #ffffff;
  border-radius: 50%;
}

.widget-last-visitors .avatar-variant-3 {
  border: 2px solid #ffffff;
  border-radius: 50%;
}

.widget-last-visitors .avatar-variant-4 {
  border: 2px solid #ffffff;
  border-radius: 50%;
}

.widget-last-visitors .avatar-variant-5 {
  border: 2px solid #ffffff;
  border-radius: 50%;
}

.widget-last-visitors .avatar-variant-6 {
  border: 2px solid #ffffff;
  border-radius: 50%;
}

.widget-last-visitors .avatar-variant-7 {
  border: 2px solid #ffffff;
  border-radius: 50%;
}

.widget-last-visitors .avatar-variant-8 {
  border: 2px solid #ffffff;
  border-radius: 50%;
}

.widget-last-visitors .avatar-variant-9 {
  border: 2px solid #ffffff;
  border-radius: 50%;
}

.widget-last-visitors .widget-title {
  font-size: 16px !important;
  line-height: 24px;
  padding-bottom: 0 !important;
}

.widget--featured-topics h3 {
  font-size: 20px !important;
  line-height: 28px;
  font-weight: 600;
}

/* .widget-last-visitors - e */
/* tags - s */
.public-tags li {
  margin-bottom: 16px !important;
  margin-right: 16px;
}

.tag--pill {
  border: 1px solid #232323;
  background: transparent;
  border-radius: 33px;
  padding: 4px 24px;
  border-radius: 33px;
  font-size: 14px;
  line-height: 22px;
  text-transform: capitalize;
}

.tag--pill.tag--active {
  background: #999999;
}

.tag--pill.tag--active:not(:hover) {
  color: #ffffff;
  border-color: #999999;
}

.tag--pill:hover {
  background: #f1f1f1;
  border-color: #232323;
  color: #232323;
}

/* tags - e */
/*.stats-bar - s */
.stats-bar .list strong {
  color: #3700FF;
}

.stats-bar .list span {
  color: #232323;
}

@media screen and (min-width: 370.11px) {
  .list--stats-bar .list__item:nth-child(2) {
    margin-left: 45px;
    margin-right: 45px;
  }
}

/*.pull - s */
.pill {
  padding: 7px 14px 4px;
  line-height: 1;
  border-radius: 99999px;
  /*&.pill--article, &.pill_idea {
      padding: 7px 14px 4px !important;
      line-height: 1;
      border-radius: 999px;
  }*/
}

.pill.pill--article.event-pill__past {
  margin-top: -4px;
}

.pill.pill_idea {
  background-color: var(--config--main-color-brand) !important;
  background-color: #00b336 !important;
}

@media (max-width: 767px) {

  .featured-topic__url:active .pill.pill,
  .featured-topic__url:focus .pill.pill,
  .featured-topic__url:hover .pill.pill {
    background-color: var(--config--main-color-brand);
    background-color: #00b336;
  }
}

/*.pull - e */
.Template-brand-cta {
  border: 0 none;
}

/* .quicklink - s */
.quicklink__container {
  flex-wrap: wrap !important;
}

.quicklink__url {
  display: -ms-flex;
  display: -moz-flex;
  display: -webkit-flex;
  display: flex;
  -webkit-justify-content: start;
  justify-content: start;
  -webkit-align-items: start;
  align-items: start;
  padding: 24px 0 0 24px;
  text-align: left;
}

.quicklink__hero {
  display: block;
  width: 1px;
  height: 60px;
  padding: 0 60px 0 0;
  margin: 0;
  background-size: cover !important;
}

.quicklink__title {
  padding-top: 0;
  padding-left: 24px;
  margin-top: 0;
}

.quicklink__title>h3 {
  font-size: 24px;
  line-height: 32px;
}

.quicklink__box {
  border-radius: 4px !important;
}

/* .quicklink - e */
/* icons - s */
i[class*=" icon"],
i[class^=icon] {
  line-height: 1;
}

.icon--eye:before {
  content: "";
  background: transparent url("https://mkto.veeam.com/lp/projects/2020/veeam-en-community.insided.com/img/icon_eye_gray.svg") no-repeat center center;
  background-size: cover;
  width: 24px;
  height: 24px;
  display: block;
}

.icon--comment:before {
  content: "";
  background: transparent url("https://mkto.veeam.com/lp/projects/2020/veeam-en-community.insided.com/img/icon_bubble_gray.svg") no-repeat center center;
  background-size: cover;
  width: 24px;
  height: 24px;
  display: block;
}

.icon--thumb-up {
  line-height: 1.5 !important;
}

.group-overview-item__meta--topics-total svg,
.group-overview-item__meta--members-total svg {
  display: none;
}

.group-overview-item__meta--topics-total:before {
  content: "";
  background: transparent url("https://mkto.veeam.com/lp/projects/2020/veeam-en-community.insided.com/img/icon_faq_gray.svg") no-repeat center center;
  background-size: cover;
  width: 24px;
  height: 24px;
  display: block;
}

.group-overview-item__meta--members-total:before {
  content: "";
  background: transparent url("https://mkto.veeam.com/lp/projects/2020/veeam-en-community.insided.com/img/icon_group_gray.svg") no-repeat center center;
  background-size: cover;
  width: 24px;
  height: 24px;
  display: block;
}

.group-details-page_action-buttons .btn.btn--cta {
  /*@include g-cta__btn-primary($color-white);
  @include btn-group();*/
}

.topic-curation__item-icon:before,
.topic-curation__item>span:before {
  content: "";
  background: transparent url("https://mkto.veeam.com/lp/projects/2020/veeam-en-community.insided.com/img/icon_technical_documentation.svg") no-repeat center center;
  background-size: cover;
  width: 24px;
  height: 24px;
  display: block;
}

.topic-curation__item-icon svg,
.topic-curation__item>span svg {
  display: none;
}

/* icons - e */
/* Button text restyle - s */
.btn {
  /* share-btn - s */
  /* share-btn - e */
}

.btn--cta,
.btn--secondary,
.btn--cancel {
  /*padding: 0 30px;
    width: auto !important;*/
}

.btn a {
  line-height: 1;
}

.btn--create-topic.btn--fixed {
  box-sizing: border-box;
  padding: 12px 30px 10px;
  text-align: center;
  line-height: 1.5;
  font-style: normal;
  font-weight: 600;
  font-stretch: normal;
  text-decoration: none;
  text-transform: uppercase;
  /*color:#fff;*/
  font-size: 16px;
  border: 0 none;
  outline: 0;
  border-radius: 99999px;
  transition: background .15s ease-in-out;
  /*@include g-cta__btn-primary($color-topaz);*/
}

.btn--create-topic.btn--fixed:hover {
  text-decoration: none;
}

.btn--create-topic.btn--fixed,
.btn--create-topic.btn--fixed:hover,
.btn--create-topic.btn--fixed:active {
  background-image: url("https://mkto.veeam.com/lp/projects/2020/veeam-en-community.insided.com/img/icon_pen_white.svg");
  background-repeat: no-repeat;
  background-position: 29px 50%;
  padding-left: 49px;
  background-size: 15px 15px;
}

.btn--create-topic.btn--fixed,
.btn--create-topic.btn--fixed:hover,
.btn--create-topic.btn--fixed:active {
  padding: 30px;
  background-position: 50% 50%;
}

.btn--create-topic.btn--fixed .icon--pen {
  display: none !important;
}

.btn--new-topic,
.btn--new-topic:hover,
.btn--new-topic:active {
  background-image: url("https://mkto.veeam.com/lp/projects/2020/veeam-en-community.insided.com/img/icon_pen_white.svg");
  background-repeat: no-repeat;
  background-position: 29px 50%;
  padding-left: 49px;
  background-size: 15px 15px;
}

.btn.btn--facebook.btn--icon,
.btn.btn--linkedin.btn--icon,
.btn.btn--mail.btn--icon,
.btn.btn--twitter.btn--icon,
.btn.btn--whatsapp.btn--icon {
  padding: 0;
}

.ask-question-widget__widget .ask-question-widget__button a {
  background-image: none;
  padding-left: 21px !important;
  padding-right: 21px !important;
}

/* Button text restyle - e */
/* breadcrumb-container - s */
.breadcrumb-container.sitewidth {
  max-width: 100%;
  overflow: hidden;
  background: #004550;
  background: var(--config-main-navigation-background-color);
}

.breadcrumb-container.sitewidth+.sitewidth:not(.breadcrumb-container) {
  margin-top: 48px;
}

.main-navigation--breadcrumb-wrapper {
  max-width: 1140px;
  margin-left: auto;
  margin-right: auto;
  float: none;
}

.main-navigation--breadcrumb-wrapper .breadcrumb .breadcrumb-item .breadcrumb-item-link {
  color: #3700FF;
}

.main-navigation--breadcrumb-wrapper .breadcrumb .breadcrumb-item .icon--caret-right,
.main-navigation--breadcrumb-wrapper .breadcrumb .breadcrumb-item .current {
  color: #232323;
}

.Template-content {
  margin-top: 48px;
}

/* breadcrumb-container - e */
.card-widget-wrapper:hover {
  border-color: #ffffff;
}

.event {
  /* https://veeam-en-community.insided.com/events/amsterdam-meetup-1 - s */
  /* https://veeam-en-community.insided.com/events/amsterdam-meetup-1 - e */
}

.event-calendar-icon-container .event__month {
  border: 2px solid #00B336;
  border-radius: 0;
  border-bottom: 0 none;
  background: #00B336;
}

.event-calendar-icon-container .event__date {
  border: 2px solid #00B336;
  border-top: 0 none;
}

.event-header__title .event__title {
  font-size: 40px !important;
  line-height: 48px;
  margin-top: 8px;
}

@media screen and (max-width: 1024px) {
  .event-header__title .event__title {
    font-size: 30px !important;
    line-height: 38px;
  }
}

@media screen and (max-width: 767px) {
  .event-header__title .event__title {
    font-size: 40px !important;
    line-height: 48px;
  }
}

.event-detail-container .event__type {
  margin-bottom: 2px;
}

.event-item__attendees>span {
  font-size: 16px;
  line-height: 24px;
}

@media screen and (max-width: 1300px) {
  .event-header-container {
    /*-ms-grid-columns: 1fr 45%;*/
    grid-template-columns: 1fr 45%;
  }
}

@media screen and (max-width: 767px) {
  .event-header-container {
    /*-ms-grid-columns: 1fr;*/
    grid-template-columns: 1fr;
  }
}

.event__attending {
  padding-left: 0 !important;
  width: initial !important;
}

.event__image {
  margin-top: 20px;
}

@media screen and (max-width: 767px) {
  .event__image {
    margin-top: 0;
  }
}

@media screen and (max-width: 767px) {

  .event-header-container .event-header-wrapper .event-attending-wrapper,
  .event-header-container .event-header-wrapper .event-cta-wrapper,
  .event-header-container .event-header-wrapper .event-engagement-wrapper {
    width: initial;
  }
}

@media screen and (max-width: 767px) {
  .event-header-container .event-header-wrapper .event-attending-wrapper {
    flex-direction: row;
    align-items: baseline;
  }
}

.event-attendees__header_label,
.event-content__header_label,
.event-details__header_label,
.event-featured-topics__header_label {
  font-size: 24px;
  line-height: 32px;
}

.event-details-container .event-detail__label {
  font-size: 16px;
  line-height: 24px;
  font-weight: 600;
}

.cke_panel_container,
.post__content.post__content--new-editor {
  font-size: 16px;
  line-height: 24px;
}

.has-border {
  border-color: #cdcdcd;
}

.featured-topics__list {
  flex-wrap: wrap !important;
}

@media screen and (max-width: 767px) {
  .featured-topics__list {
    padding-right: 0 !important;
  }
}

@media screen and (max-width: 767px) {
  .featured-topics .featured-topic {
    border-right-width: 15px;
    margin-right: 0;
    width: 100%;
  }
}

@media screen and (max-width: 767px) {
  .featured-topics .featured-topic.featured-topic--full-width {
    margin-right: 0 !important;
  }
}

.featured-topics .featured-topic.featured-topic--half-width .event-list-item__url {
  width: 100%;
}

.featured-topics .featured-topic.featured-topic--half-width .event-list-item__url .event-list-item-container {
  width: 100%;
}

@media screen and (max-width: 767px) {
  .featured-topic__url {
    width: 100%;
  }
}

.featured-topic__heading {
  font-size: 24px;
  line-height: 32px;
}

.featured-topic__title {
  display: block;
  display: grid;
}

.leaderboard-username {
  font-size: 16px;
}

.leaderboard-container .leaderboard-row>td {
  padding-bottom: 23px;
}

.leaderboard-container .position-container {
  width: 32px;
  height: 32px;
  margin-top: 7px;
}

.leaderboard-container .position-number {
  font-weight: bold;
  /*background-size: 32px 32px;*/
  background: transparent;
  background-position: 50% 50%;
  background-repeat: no-repeat;
  background-size: contain;
  text-align: center;
  color: #fff;
  width: 32px;
}

.leaderboard-container .position-number-top {
  background-image: url("https://mkto.veeam.com/lp/projects/2020/veeam-en-community.insided.com/img/icon_star_top.svg");
}

.leaderboard-container .position-number-other {
  background-image: url("https://mkto.veeam.com/lp/projects/2020/veeam-en-community.insided.com/img/icon_star.svg");
  color: var(--config--main-color-brand);
  border: 0 none;
  color: #3700FF;
}

.flag .flag__image>img {
  width: 42px;
  height: auto;
}

/* https://veeam-en-community.insided.com/members/kseniya-9 -- s */
.box--user-badges .qa-user-badges-list img {
  width: 100px;
  height: auto;
}

/* https://veeam-en-community.insided.com/members/kseniya-9 -- e */
.userprofile-personal .qa-username {
  font-size: 24px;
  line-height: 32px;
  font-weight: 500;
}

.qa-user-badges {
  font-size: 24px;
  line-height: 32px;
  font-weight: 500;
}

.qa-user-profile-fields .box-title {
  font-size: 24px;
  line-height: 32px;
  font-weight: 500;
}

.qa-link-tab:hover {
  color: #3700FF !important;
}

.qa-user-statistics {
  padding-top: 0 !important;
}

.link:hover {
  color: #00D03F;
}

.link--user:hover,
.thread-list-item a.link--user:hover,
.thread-meta-link--default-color:hover {
  color: #3700FF;
}

.font--meta .link:hover,
.link--quiet:hover {
  color: #3700FF !important;
}

.font--meta .link:hover.is-active,
.link--quiet:hover.is-active {
  color: #00b492 !important;
}

.post:hover .post__actions>li .is-active,
.post:hover .post__actions>li .is-active.icon--b:before,
.post__actions>li .is-active,
.post__actions>li .is-active.icon--b:before,
.public-tags .canEditTags .link.tag--modify {
  color: #00b336;
}

/* WOW - additional - s */
.idea-view .topic-view_footer .thread-meta-item--vote {
  top: 36px;
}

/* WOW - additional - e */
.thread {
  /* WOW - s */
  /* WOW - e */
}

.thread-list-block__title {
  font-size: 20px;
  line-height: 28px;
  margin-bottom: 8px;
  font-weight: 600;
}

.thread-list-avatar {
  margin-right: 11px;
}

.thread-meta-item--likes,
.thread-meta-item--vote {
  font: normal 16px/24px 'Guardian TextSans Cy', 'Guardian TextSans', Tahoma, sans-serif;
}

@media screen and (max-width: 767px) {
  .thread .ideation-topic-votes .ideation-topic-votes-wrapper .thread-meta-item--vote {
    justify-content: flex-end;
  }
}

.thread-meta-item.btn--toggle,
.thread--user-liked .thread-meta-item--likes .btn--toggle {
  font-weight: bold;
  border: 0 none !important;
  background: transparent !important;
  box-shadow: none !important;
}

.thread-meta-item.btn--toggle svg,
.thread--user-liked .thread-meta-item--likes .btn--toggle svg {
  display: none;
}

@media screen and (max-width: 1024px) {

  .thread-meta-item.btn--toggle,
  .thread--user-liked .thread-meta-item--likes .btn--toggle {
    margin-right: 15px;
  }
}

@media screen and (max-width: 767px) {

  .thread-meta-item.btn--toggle,
  .thread--user-liked .thread-meta-item--likes .btn--toggle {
    padding: 0;
    height: 0;
  }
}

.thread-meta-item.btn--toggle,
.thread-meta-item.btn--toggle:hover,
.thread-meta-item.btn--toggle:active,
.thread-meta-item.btn--toggle.preact_voted,
.thread--user-liked .thread-meta-item--likes .btn--toggle,
.thread--user-liked .thread-meta-item--likes .btn--toggle:hover,
.thread--user-liked .thread-meta-item--likes .btn--toggle:active,
.thread--user-liked .thread-meta-item--likes .btn--toggle.preact_voted {
  color: #00b336;
  min-height: 73px;
}

@media screen and (min-width: 768px) {

  .thread-meta-item.btn--toggle,
  .thread-meta-item.btn--toggle:hover,
  .thread-meta-item.btn--toggle:active,
  .thread-meta-item.btn--toggle.preact_voted,
  .thread--user-liked .thread-meta-item--likes .btn--toggle,
  .thread--user-liked .thread-meta-item--likes .btn--toggle:hover,
  .thread--user-liked .thread-meta-item--likes .btn--toggle:active,
  .thread--user-liked .thread-meta-item--likes .btn--toggle.preact_voted {
    padding-left: 0;
  }
}

@media screen and (max-width: 767px) {

  .thread-meta-item.btn--toggle,
  .thread-meta-item.btn--toggle:hover,
  .thread-meta-item.btn--toggle:active,
  .thread-meta-item.btn--toggle.preact_voted,
  .thread--user-liked .thread-meta-item--likes .btn--toggle,
  .thread--user-liked .thread-meta-item--likes .btn--toggle:hover,
  .thread--user-liked .thread-meta-item--likes .btn--toggle:active,
  .thread--user-liked .thread-meta-item--likes .btn--toggle.preact_voted {
    justify-content: flex-end !important;
  }
}

.thread-meta-item.btn--toggle:hover,
.thread--user-liked .thread-meta-item--likes .btn--toggle:hover {
  color: #00b336;
}

.thread-meta-item.btn--toggle:active,
.thread-meta-item.btn--toggle.preact_voted,
.thread--user-liked .thread-meta-item--likes .btn--toggle:active,
.thread--user-liked .thread-meta-item--likes .btn--toggle.preact_voted {
  color: #004550;
}

.thread-meta-item.btn--toggle:active .qa-topic-meta-likes-content:before,
.thread-meta-item.btn--toggle.preact_voted .qa-topic-meta-likes-content:before,
.thread--user-liked .thread-meta-item--likes .btn--toggle:active .qa-topic-meta-likes-content:before,
.thread--user-liked .thread-meta-item--likes .btn--toggle.preact_voted .qa-topic-meta-likes-content:before {
  content: "Liked!";
  padding-right: 16px;
  background-image: url("https://mkto.veeam.com/lp/projects/2020/veeam-en-community.insided.com/img/icon_like_activate.svg?20200102");
}

.thread-meta-item.btn--toggle:active .qa-topic-meta-likes-content:after,
.thread-meta-item.btn--toggle.preact_voted .qa-topic-meta-likes-content:after,
.thread--user-liked .thread-meta-item--likes .btn--toggle:active .qa-topic-meta-likes-content:after,
.thread--user-liked .thread-meta-item--likes .btn--toggle.preact_voted .qa-topic-meta-likes-content:after {
  left: 51px;
}

.thread-meta-item.btn--toggle .qa-topic-meta-likes-content,
.thread--user-liked .thread-meta-item--likes .btn--toggle .qa-topic-meta-likes-content {
  position: relative;
  text-transform: capitalize;
  /*padding-left: 0;*/
  margin-left: 0 !important;
}

@media screen and (min-width: 768px) {

  .thread-meta-item.btn--toggle .qa-topic-meta-likes-content,
  .thread--user-liked .thread-meta-item--likes .btn--toggle .qa-topic-meta-likes-content {
    padding-left: 0;
  }
}

@media screen and (max-width: 767px) {

  .thread-meta-item.btn--toggle .qa-topic-meta-likes-content,
  .thread--user-liked .thread-meta-item--likes .btn--toggle .qa-topic-meta-likes-content {
    justify-content: flex-end !important;
  }
}

.thread-meta-item.btn--toggle .qa-topic-meta-likes-content:before,
.thread--user-liked .thread-meta-item--likes .btn--toggle .qa-topic-meta-likes-content:before {
  content: "Like!";
  font-family: ESBuild, Tahoma, "Trebuchet MS", sans-serif;
  display: inline-block;
  font-weight: bold;
  font-size: 16px;
  line-height: 24px;
  padding-right: 12px;
  padding-top: 76px;
  top: -76px;
  background-color: transparent;
  background-image: url("https://mkto.veeam.com/lp/projects/2020/veeam-en-community.insided.com/img/icon_like.svg");
  background-size: 48px 48px;
  background-repeat: no-repeat;
  background-position: 100% 50%;
}

@media screen and (max-width: 767px) {

  .thread-meta-item.btn--toggle .qa-topic-meta-likes-content:before,
  .thread--user-liked .thread-meta-item--likes .btn--toggle .qa-topic-meta-likes-content:before {
    padding-top: 49px;
    background-position: 100% 0%;
  }
}

.thread-meta-item.btn--toggle .qa-topic-meta-likes-content:after,
.thread--user-liked .thread-meta-item--likes .btn--toggle .qa-topic-meta-likes-content:after {
  content: ".";
  position: absolute;
  left: 41px;
  bottom: 8px;
  font-weight: bold;
  font-size: 16px;
  line-height: 1;
}

.topic {
  /*&__header {
      padding-left: 0;
      padding-right: 0;
  }*/
}

.topic-view {
  /* WOW - s */
  /* WOW - e */
}

@media screen and (min-width: 768px) {
  .topic-view {
    padding-left: 92px;
  }
}

@media screen and (max-width: 767px) {
  .topic-view.topic-view--ideation .topic-view_info {
    padding-bottom: 54px;
  }
}

@media screen and (min-width: 768.11px) {
  .topic-view {
    /* for --likes */
  }

  .topic-view .topic-view_info {
    position: initial;
    padding-right: 80px;
  }
}

@media screen and (max-width: 767px) {
  .topic-view.topic-view--ideation .topic-view_info {
    padding-bottom: 0;
  }
}

@media screen and (max-width: 767px) {
  .topic-view .topic-view_footer {
    position: relative;
  }
}

.topic__title {
  font-size: 24px;
  line-height: 32px;
}

.topic-curation-destination__container .topic-curation__item .topic-curation__item-body .topic-curation__title.thread-list-block__title {
  font-size: 20px;
  line-height: 28px;
}

input[type=email],
input[type=password],
input[type=search],
input[type=text],
select,
select[multiple],
textarea {
  border-color: #cdcdcd;
}

input[type=email]:focus,
input[type=password]:focus,
input[type=search]:focus,
input[type=text]:focus,
select:focus,
select[multiple]:focus,
textarea:focus {
  border-color: #00b336;
}

/* checkbox - s */
div[class*="__label-wrapper"] div[class*="--checkbox"]>label {
  display: block;
  padding-left: 36px;
  font-size: 16px;
  position: relative;
}

div[class*="__label-wrapper"] div[class*="--checkbox"]>label::before {
  box-sizing: border-box;
  position: absolute;
  content: '';
  top: 0;
  left: 0;
  width: 20px;
  height: 20px;
  background: #fff;
  background-size: 11px;
  border: 1px solid #999999;
  cursor: pointer;
  transition: border ease-out 0.3s;
}

div[class*="__label-wrapper"] div[class*="--checkbox"]>label:hover::before {
  border: 1px solid #005F4B;
}

div[class*="__label-wrapper"] div[class*="--checkbox"]>label input {
  display: none;
}

div[class*="__label-wrapper"].refined div[class*="--checkbox"]>label {
  font-weight: normal !important;
  color: #232323 !important;
}

div[class*="__label-wrapper"].refined div[class*="--checkbox"]>label::before {
  background: #fff url("https://psr.veeam.com/global/img/icon/checkbox_checked_00b336.svg") no-repeat center center;
  border: 1px solid #00B336;
}

/* checkbox - e */
.social-sharing .tooltip-container .tooltip-trigger .share-button,
.social-sharing .tooltip-container .tooltip-trigger .share-button:hover {
  padding: 11px;
  color: #00b336;
}

.custom-html-widget-wrapper {
  margin-top: 0;
}

.submit-idea {
  margin-bottom: 40px;
}

@media screen and (max-width: 768px) {
  .submit-idea {
    padding-left: 16px;
    padding-right: 16px;
  }
}

.submit-idea__box {
  margin-right: 0;
}

.submit-idea__bgr-img {
  background-image: url("https://mkto.veeam.com/lp/projects/2020/veeam-en-community.insided.com/img/icon_bulb_teal.svg");
}

/*  ************************************************* GM - e  ************************************************* */
.brand-hero .brand-hero-title,
.forum-featured-image__content .forum-list-view-description,
.forum-featured-image__content .hero-subforum-title {
  color: #fff;
}

/*Header font weight*/
h1,
h2,
h3,
h4,
h5,
.topic__title {
  font-weight: 500;
  /* GM -- upd from 800 to 500 */
}

.h1,
h1 {
  font-size: 24px;
  line-height: 32px;
  margin-bottom: 24px;
}

/*search bar style*/
input[type=search].search-box__input {
  /*border-radius: 4px !important; -------- GM */
  /*box-shadow: none !important; -------- GM*/
  /*border: 1px solid #e3e4ec !important; ------- GM */
}

/*change shadow and border radius for live search dropdown*/
.algolia-hit-container {
  /*border-radius: 4px !important; -------- GM */
  box-shadow: rgba(0, 0, 0, 0.1) 0px 2px 9px 0px !important;
}

/*change styles for parent category cards on homepage*/
.community-category-container .community-category__card {
  /* border-radius: 4px; -------- GM */
  /*border: 1px solid #e3e4ec !important; ------- GM */
  box-shadow: none;
}

.featured-topic__url {
  /* border-radius: 4px; -------- GM */
  /*border: 1px solid #e3e4ec; -------- GM */
}

.featured-topic__url:hover,
.featured-topic__url:active {
  border: 1px solid transparent;
}

/*featured topics on category pages*/
.widget--featured-topics .widget--featured-carousel .swiper-container .swiper-container-horizontal {
  /* border-radius: 4px; -------- GM */
  /*border: 1px solid #e3e4ec !important; ------- GM */
}

/*change static bar background color*/
.stats-bar {
  /* GM */
  height: auto;
  padding: 35px 0 30px;
}

.stats-bar .p-v .qa-stats-bar {
  background-color: #f8f8f8;
}

/*category page search bar*/
.custom-stats-bar {
  border-bottom: none;
  margin-top: 0;
}

.custom-stats-bar .stats-bar {
  background-color: #ffffff;
  box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.05);
  padding-top: 34px;
  padding-bottom: 30px;
}

/*featured topics categories*/
.widget--featured-topics .featured-topic {
  /*border: 1px solid #e3e4ec; -------- GM */
  /*box-shadow: none; -------- GM */
  /* border-radius: 4px; -------- GM */
}

/*widget title margin*/
.widget title add {
  margin-top: 16px;
}

/* hero banner change height */
.custom-hero-banner {
  /* height: 300px; */
  /* -- hidden by GM ---  default: 240px */
}

/* KB cards */
.quicklink__box {
  /*border: 1px solid #e3e4ec; -------- GM */
  /*border-radius: 4px !important; -------- GM */
}

.quicklink__box:hover {
  border: 1px solid transparent;
}

iframe#twitter-widget-0 {
  border: 1px solid #E3E4EC !important;
  /*border-radius: 4px !important; -------- GM */
}

@media (max-width: 1024px) {
  .widget---leaderboard_points {
    margin-top: 32px;
  }
}

@media (max-width: 420px) {
  .custom-hero-banner {
    /* height: 200px;
    padding-top: 40px; -- hidden by GM */
  }
}

@media (min-width: 768px) {

  /*change styles for category cards on parent category page*/
  .category-page_container .category-page_list .category-page_list-item {
    /* border-radius: 4px; -------- GM */
    /*border: 1px solid #e3e4ec !important; ------- GM */
    /*box-shadow: none !important; ------- GM */
  }

  /*add border-radius to topic list*/
  .topic-list-view {
    /* border-radius: 4px; -------- GM */
  }

  .custom-content-stream .qa-topic-block:last-child {
    border-bottom-right-radius: 8px;
    border-bottom-left-radius: 8px;
  }

  .custom-content-stream .qa-topic-block:first-child {
    border-top-right-radius: 8px;
    border-top-left-radius: 8px;
  }

  .custom-content-stream .load-more-container {
    border-bottom-right-radius: 8px;
    border-bottom-left-radius: 8px;
  }

  .qa-topic-first-post {
    /* border-radius: 4px; -------- GM */
  }

  #comments {
    /* border-radius: 4px; -------- GM */
  }

  #comments+.box__pad {
    /* border-radius: 4px; -------- GM */
  }

  .qa-topic-reply-box-header {
    border-top-right-radius: 8px;
    border-top-left-radius: 8px;
  }

  .custom-content-stream .forum-list {
    /* border-radius: 4px; -------- GM */
  }

  .custom-content-stream .forum-list>.box:first-child {
    border-top-right-radius: 8px;
    border-top-left-radius: 8px;
  }

  .custom-content-stream .forum-list>.box:last-child {
    border-bottom-right-radius: 8px;
    border-bottom-left-radius: 8px;
  }
}

@media (min-width: 1024px) {
  .qa-div-main.widget-wrapper .box {
    border-radius: 8px;
  }

  .qa-div-main.widget-wrapper .list__items--header {
    border-top-right-radius: 8px;
    border-top-left-radius: 8px;
  }

  .qa-div-main.widget-wrapper .qa-topic-block:last-child {
    border-bottom-right-radius: 8px;
    border-bottom-left-radius: 8px;
  }
}

/* Need more help section in kb page */
.ask-question-widget__widget {
  /*border: 1px solid #E3E4EC; -------- GM */
}

.ask-question-widget__title {
  font-size: 16px !important;
  font-weight: 600;
}

@media (min-width: 1025px) {
  .ask-question-widget__widget {
    /*border-radius: 4px !important; -------- GM */
  }
}

/* Add radius to sections in kb category page*/
@media (min-width: 1025px) {
  .topic-curation-destination__container {
    /* border-radius: 4px; -------- GM */
  }
}

/*  */
@media (min-width: 1025px) {
  .avatar--XL {
    height: 100px !important;
    width: 100px !important;
  }
}

.fancyselect input[type=checkbox]+label:before {
  color: currentcolor !important;
}

.fancyselect input[type=radio]+label:before {
  color: currentcolor !important;
}

/* GM - HTML-26752 */
.avatar--responsive .profilepicture {
  position: relative;
}

.thread-list-avatar .default-avatar {
  line-height: 1;
  position: absolute;
}

.default-avatar-link,
.profilepicture a.default-avatar-link {
  padding: 0;
  margin: 0;
  line-height: 0;
}


p.card-widget-text {
  overflow: unset !important;
}

/*hide Meta social media share buttons*/
.btn.btn--icon.btn--facebook.qa-button-facebook {
  display: none;
}

/*Fix for register button*/
@media screen and (min-width: 768px) {
  .event-header-container {
    grid-template-rows: 325px max-content !important;
  }
}

.group-overview-wrapper-title {
  background-image: url("https://i.postimg.cc/RCQdVkPw/Frame-422-2.png");
  height: 240px;
  background-size: center;
  align-items: center;
  justify-content: center;
  display: flex;
  margin-bottom: 3px;
  margin-top: 10px;
  color: white;
}

.header-navigation .header-navigation-items_menu:after,
.main-navigation--wrapper,
.main-navigation--nav-buttons-wrapper,
.header-navigation .header-navigation_extendable-search {
  background: #fff;
}

.main-menu-trigger,
.main-menu-trigger span,
.main-menu-trigger path {
  filter: brightness(.3);
  color: #232323;
}

.header-navigation-items_menu>li {
  margin-bottom: 0;
}

.search-box>* {
  color: #fff;
}

.tabs__item>.is-active,
.tabs__item>.tabs__btn--active {
  border-bottom: 4px solid #3700FF !important;
}

/* .Sidebarmodule .btn--show-more, .Sidebarmodule .btn--show-more:hover {
     color: #3700FF;
 }

 .leaderboard-container .leaderboard-username .username:hover {
     color: #3700FF;
 }*/

.Sidebarmodule .widget .username:hover,
.event-detail-container .event__title:hover,
.leaderboard-container .leaderboard-username .username:hover,
.Sidebarmodule .btn--show-more,
.Sidebarmodule .btn--show-more:hover,
.templatefoot-privacy-links a:hover {
  color: #3700FF;
}

.header-navigation .header-navigation-items_menu {
  align-items: center;
}

.main-navigation--language-switcher_dropdown {
  background-color: #fff;
  border: 1px solid #000;
}

.widget--badges a {
  font-size: 16px;
}

.main-menu-list__item--no-hover>:hover,
.main-menu-list__item--highlighted,
.link--text:hover {
  color: #3700FF;
}

.header-navigation .header-navigation-items_hamburger .slider-trigger {
  color: #232323;
  cursor: pointer;
}

@media screen and (max-width: 1024px) {

  .header-navigation .header-navigation_link:hover,
  .main-menu-trigger span:hover {
    color: #3700FF;
  }

  .main-menu-trigger,
  .main-menu-trigger span,
  .main-menu-trigger path {
    filter: brightness(1);
  }
}

#modal_report .btn,
.btn,
.btn--cancel,
.btn--cta,
.btn--insided-brand,
.btn--insided-secondary-brand,
.btn--new-topic,
.btn--purple,
.btn--secondary,
.btn--silent,
.btn--toggle,
.btn--toggle-on,
.btn--toggle.is-active,
.btn--toggle.is-follow,
.btn--toggle.preact_voted,
.btn--toggle.thread-meta-item,
.event-header-container .event-header-wrapper .event__attended,
.event-header-container .event-header-wrapper .event__attended:hover,
.event-header-container .event-header-wrapper .event__attending,
.event-header-container .event-header-wrapper .event__attending:hover,
.event-header-container .event-header-wrapper .event__ended,
.event-header-container .event-header-wrapper .event__ended:hover,
.homepage-widget-configurator .homepage-widget-configurator__controls .btn-primary,
.homepage-widget-configurator .widget-configurator__controls .btn-primary,
.offline-community .btn,
.private-register .btn,
.thread--user-liked .thread-meta-item--likes .btn--toggle,
.widget-configurator .homepage-widget-configurator__controls .btn-primary,
.widget-configurator .widget-configurator__controls .btn-primary,
.wysiwyg-editor.wysiwyg-editor-profile__forum_pm .wysiwyg-editor__submit-button,
.wysiwyg-editor .wysiwyg-editor__form-submit,
.wysiwyg-editor .wysiwyg-editor__link--selector .btn,
.wysiwyg-editor .wysiwyg-editor__submit-button {
  border-radius: 6px;
}

.header-navigation .main-navigation--nav-buttons-wrapper .btn > svg {
        width: auto;
        min-width: 16px;
    }
body.twig_page-topic.category-163 .widget--related-topics, body.twig_page-topic.category-163 .breadcrumb-container {
    display: none;
}
body.twig_page-topic.category-175 .widget--related-topics, body.twig_page-topic.category-175 .breadcrumb-container {
    display: none;
}
body.twig_page-topic.category-176 .widget--related-topics, body.twig_page-topic.category-176 .breadcrumb-container {
    display: none;
}
body.twig_page-topic.category-179 .widget--related-topics, body.twig_page-topic.category-179 .breadcrumb-container {
    display: none;
}
body.twig_page-topic.category-186 .widget--related-topics, body.twig_page-topic.category-186 .breadcrumb-container {
    display: none;
}
body.twig_page-topic.category-177 .widget--related-topics, body.twig_page-topic.category-177 .breadcrumb-container {
    display: none;
}body.twig_page-topic.category-185 .widget--related-topics, body.twig_page-topic.category-185 .breadcrumb-container {
    display: none;
}
body.twig_page-topic.category-187 .widget--related-topics, body.twig_page-topic.category-187 .breadcrumb-container {
    display: none;
} </style>
</head>

<body id="customcss" class="twig_page-topic category-67 topic-264">
<div data-preact="destination/modules/Accessibility/SkipToContent/SkipToContent" class="" data-props="{}"><a href="#main-content-target" class="skip-to-content-btn" aria-label>Skip to main content</a></div>
<link href="https://fonts.googleapis.com/css?family=Open+Sans:300,400,600,700,800,300italic,400italic,600italic&amp;display=swap" rel="stylesheet"/>
<!--
<html>
<head>
	<style>
		body {
			margin: 0;
			padding: 0;
		}
		
		.header-component__messages {
			display: none;
		}
	
		.cookie-messaging {
			width: 100%;
			background: #f1f1f1;
			z-index: 999999;
			position: relative;
			
			box-sizing: border-box;
		}
		
		.cookie-messaging__container {
			display: flex;
			align-items: center;
			justify-content: space-between;
			max-width: 1220px;
			margin: 0 auto;
			padding: 30px 10px;
		}

		.cookie-messaging__message {
			margin-right: 30px;
		}
		
		.cookie-messaging__title {
			font-family: "Guardian TextSans", Helvetica, "Arial", sans-serif;
			font-weight: 700;
			font-style: normal;
			font-stretch: normal;
			font-size: 19px;
			line-height: 27px;
		}
		
		.cookie-messaging__text {
			margin: 0;
		}

		.cookie-messaging__button {
			transition: background .15s ease-in-out;
			text-align: center;
			border-radius: 24px;
			padding: 0 32px;
			font-size: 16px;
			height: 48px;
			line-height: 48px;
			border: none;
			outline: none;
			font-family: "Guardian TextSans", Helvetica, "Arial", sans-serif;
			font-weight: 700;
			font-style: normal;
			font-stretch: normal;
			background: #00b336;
			color: #ffffff;
			text-decoration: none;
			cursor: pointer;
			white-space: nowrap;
			display: inline-block;
			text-transform: uppercase;
		}
		
		.cookie-messaging__button:hover, 
		.cookie-messaging__button:focus {
			background: #00c73c;
			color: #ffffff !important;
		}
		
		.cookie-messaging__button:active {
			background: #009e30;
			color: #ffffff !important;
		}
		
		@media (max-width: 1259px) {
			.header-component__messages-overlay {
				display: block;
				position: fixed;
				background: rgba(0, 0, 0, 0.6);
				width: 100%;
				height: 100%;
				z-index: 999998;
				top: 0;
				left: 0;
			}
			
			
			.header-component__messages {
				position: fixed;
				width: 100%;
				bottom: 0;
				z-index: 9999999;
			}
		}
      
      .fancyselect input[type=checkbox]+label:before{
      	    color: currentcolor !important;
      }
      
      .fancyselect input[type=radio]+label:before {
        	color: currentcolor !important;
      }
	</style>
	
	<!-- JQuery is necessary for script. You may rewrite script logic to use it without jQuery -->
<!--	
<script
  src="https://code.jquery.com/jquery-3.5.1.min.js"
  integrity="sha256-9/aliU8dGd2tb6OSsuzixeV4y/faTqgFtohetphbbj0="
  crossorigin="anonymous"></script>
	<script>
		$(function() {
			if (document.cookie.indexOf('hideCookieNotice') === -1) {
				$('.js-header-notifications').show();
			}
			
			$('.js-cookie-btn-close').on('click', function() {
				var cookie = 'hideCookieNotice=1;domain=.veeam.com;path=/';
				cookie += ';expires=' + getExpirationDate();
				document.cookie = cookie;
				$('.js-header-notifications').fadeOut();
				return false;
			});
			
			function getExpirationDate() {
				CookieDate = new Date;
				CookieDate.setFullYear(CookieDate.getFullYear() + 1);
				return CookieDate.toGMTString();
			}
		});
	</script>
</head>
<body>
	<div class="header-component__messages js-header-notifications">
		<div class="cookie-messaging">
			<div class="cookie-messaging__container">
				<div class="cookie-messaging__message">
					<b class="cookie-messaging__title">Our website uses cookies!</b>
					<p class="cookie-messaging__text">By continuing to use our website, you agree with our use of cookies in accordance with our <a href="https://www.veeam.com/privacy-policy.html#cookie">Cookie Policy</a>. You can reject cookies by changing your browser settings.</p>
				</div>
				<a class="cookie-messaging__button js-cookie-btn-close" href="#">OK, GOT IT!</a>
			</div>
		</div>
		<div class="header-component__messages-overlay js-header-notifications-overlay"></div>
	</div>
</body>
</html>

-->
<div id="community-id" data-data=veeam-en ></div>
<div id="device-type" data-data=desktop ></div>
<div id="list-views-use-card-theme" data-data=0 ></div>

    <main id='root' class='body-wrapper'>
                                                                                                                                            
    <div class="ssi ssi-header custom-header">
                                <!--	<link href="https://fonts.googleapis.com/css?family=Open+Sans:300,400,600,700,800,300italic,400italic,600italic&amp;display=swap" rel="stylesheet"/>
-->
            </div>
                                                            
                                            
                                    <div class="sitewidth flash-message-wrapper">
    <div class="col">
                    <div class="module templatehead">
                



            </div>
            </div>
</div>                    <div data-preact="widget-notification/FeaturedTopicsWrapper" class="" data-props="{&quot;widget&quot;:&quot;featuredBanner&quot;}"></div>
                                                                                                                                                
                        
    



<div data-preact="mega-menu/index" class="" data-props="{&quot;logo&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/e0f13e7d-e6fd-4e9b-9826-586dfcab9b54.png&quot;,&quot;newTopicURL&quot;:&quot;\/topic\/new&quot;,&quot;groupCount&quot;:52,&quot;communityCategoriesV2&quot;:[{&quot;id&quot;:40,&quot;type&quot;:0,&quot;title&quot;:&quot;Community&quot;,&quot;description&quot;:&quot;News, guidelines and various community projects &quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:null,&quot;isContainer&quot;:true,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[{&quot;id&quot;:56,&quot;type&quot;:0,&quot;title&quot;:&quot;News&quot;,&quot;description&quot;:&quot;Check out the latest Veeam community news &quot;,&quot;thumbnailImage&quot;:&quot;8186b121-72f5-46d1-84c5-0b6be71f5668_thumb.png&quot;,&quot;parentId&quot;:40,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:263,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/news-56&quot;},{&quot;id&quot;:58,&quot;type&quot;:0,&quot;title&quot;:&quot;General Information&quot;,&quot;description&quot;:&quot;Getting started with the Community Resource Hub&quot;,&quot;thumbnailImage&quot;:&quot;ecd153e2-2e56-4b72-9b1d-f3bcdffeebd7_thumb.png&quot;,&quot;parentId&quot;:40,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:8,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/general-information-58&quot;},{&quot;id&quot;:57,&quot;type&quot;:0,&quot;title&quot;:&quot;Blogs and Podcasts&quot;,&quot;description&quot;:&quot;Bring your knowledge and expertise while creating blogs and podcasts&quot;,&quot;thumbnailImage&quot;:&quot;f27806ad-6cce-4ab4-81a0-8cbd8139d4e2_thumb.png&quot;,&quot;parentId&quot;:40,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:1400,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/blogs-and-podcasts-57&quot;},{&quot;id&quot;:67,&quot;type&quot;:0,&quot;title&quot;:&quot;YARA and Script Library&quot;,&quot;description&quot;:&quot;Download featured YARA rules, browse code samples or contribute your own scripts&quot;,&quot;thumbnailImage&quot;:&quot;14ad2152-b7e0-4c24-b424-e7e2801e2c72_thumb.png&quot;,&quot;parentId&quot;:40,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:179,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/yara-and-script-library-67&quot;},{&quot;id&quot;:66,&quot;type&quot;:0,&quot;title&quot;:&quot;Discussion Boards&quot;,&quot;description&quot;:&quot;Join discussions around Veeam community projects, Veeam events, industry and technology news&quot;,&quot;thumbnailImage&quot;:&quot;dcb3c235-9ba0-40df-9de9-6a8a8a2708d1_thumb.png&quot;,&quot;parentId&quot;:40,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:3463,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/discussion-boards-66&quot;},{&quot;id&quot;:141,&quot;type&quot;:0,&quot;title&quot;:&quot;VeeamON Events&quot;,&quot;description&quot;:&quot;Stay updated with the latest event news and announcements.&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:40,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:32,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/veeamon-events-141&quot;}],&quot;language&quot;:&quot;en&quot;,&quot;visibleTopicsCount&quot;:5345,&quot;containerCategoriesCount&quot;:0,&quot;contentCategoriesCount&quot;:6,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/community-40&quot;},{&quot;id&quot;:126,&quot;type&quot;:0,&quot;title&quot;:&quot;Security Blueprints&quot;,&quot;description&quot;:&quot;From Veeam's Solutions Architects!&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:null,&quot;isContainer&quot;:true,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[{&quot;id&quot;:127,&quot;type&quot;:0,&quot;title&quot;:&quot;Veeam Backup &amp; Replication&quot;,&quot;description&quot;:&quot;Reference architecture documents related to common Veeam Backup &amp; Replication scenarios encountered in the field&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:126,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:38,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/veeam-backup-replication-127&quot;},{&quot;id&quot;:128,&quot;type&quot;:0,&quot;title&quot;:&quot;Cloud Backup &quot;,&quot;description&quot;:&quot;Reference architecture documents related to common Veeam Cloud Backup products scenarios encountered in the field&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:126,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:6,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/cloud-backup-128&quot;},{&quot;id&quot;:130,&quot;type&quot;:0,&quot;title&quot;:&quot;Monitoring&quot;,&quot;description&quot;:&quot;Reference architecture documents related to common Veeam products scenarios encountered in the field&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:126,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:3,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/monitoring-130&quot;},{&quot;id&quot;:131,&quot;type&quot;:0,&quot;title&quot;:&quot;SaaS&quot;,&quot;description&quot;:&quot;Reference architecture documents related to common Veeam SaaS Backup products scenarios encountered in the field&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:126,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:3,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/saas-131&quot;},{&quot;id&quot;:132,&quot;type&quot;:0,&quot;title&quot;:&quot;Kasten&quot;,&quot;description&quot;:&quot;Reference architecture documents related to common Veeam Kasten K10 scenarios encountered in the field&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:126,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:3,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/kasten-132&quot;},{&quot;id&quot;:133,&quot;type&quot;:0,&quot;title&quot;:&quot;Databases&quot;,&quot;description&quot;:&quot; Reference architecture documents related to common Veeam database backup products scenarios encountered in the field&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:126,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:3,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/databases-133&quot;},{&quot;id&quot;:150,&quot;type&quot;:0,&quot;title&quot;:&quot;Alliance Vendor&quot;,&quot;description&quot;:&quot;Reference architecture documents related to common Veeam Backup &amp; Replication scenarios using alliance vendors hardware target&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:126,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:23,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/alliance-vendor-150&quot;},{&quot;id&quot;:182,&quot;type&quot;:0,&quot;title&quot;:&quot;Veeam Data Cloud&quot;,&quot;description&quot;:&quot;Reference architecture documents related to common Veeam Data Cloud scenarios encountered in the field&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:126,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:9,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/veeam-data-cloud-182&quot;}],&quot;language&quot;:&quot;en&quot;,&quot;visibleTopicsCount&quot;:88,&quot;containerCategoriesCount&quot;:0,&quot;contentCategoriesCount&quot;:8,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/security-blueprints-126&quot;},{&quot;id&quot;:162,&quot;type&quot;:0,&quot;title&quot;:&quot;Veeam University FREE&quot;,&quot;description&quot;:&quot;On-Demand Product Training&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:null,&quot;isContainer&quot;:true,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[{&quot;id&quot;:183,&quot;type&quot;:0,&quot;title&quot;:&quot;Self-Managed Deployment&quot;,&quot;description&quot;:&quot;Onboarding content for self-managed products&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:162,&quot;isContainer&quot;:true,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[{&quot;id&quot;:163,&quot;type&quot;:0,&quot;title&quot;:&quot;Onboarding for Veeam Data Platform&quot;,&quot;description&quot;:&quot;Essential first steps for a smooth Veeam Data Platform deployment&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:183,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:45,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/onboarding-for-veeam-data-platform-163&quot;},{&quot;id&quot;:175,&quot;type&quot;:0,&quot;title&quot;:&quot;Onboarding for Veeam Recovery Orchestrator&quot;,&quot;description&quot;:&quot;Fast-track your disaster recovery automation with Veeam Recovery Orchestrator&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:183,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:9,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/onboarding-for-veeam-recovery-orchestrator-175&quot;},{&quot;id&quot;:176,&quot;type&quot;:0,&quot;title&quot;:&quot;Onboarding for Veeam Backup for Microsoft 365&quot;,&quot;description&quot;:&quot;Protect your Microsoft 365 data with confidence\u2014get started with Veeam Backup&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:183,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:15,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/onboarding-for-veeam-backup-for-microsoft-365-176&quot;},{&quot;id&quot;:179,&quot;type&quot;:0,&quot;title&quot;:&quot; Onboarding for Veeam Kasten for Kubernetes&quot;,&quot;description&quot;:&quot;Empower your Kubernetes with trusted protection from Veeam Kasten&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:183,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:9,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/onboarding-for-veeam-kasten-for-kubernetes-179&quot;}],&quot;visibleTopicsCount&quot;:78,&quot;containerCategoriesCount&quot;:0,&quot;contentCategoriesCount&quot;:4,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/self-managed-deployment-183&quot;},{&quot;id&quot;:184,&quot;type&quot;:0,&quot;title&quot;:&quot;Veeam-Hosted Services&quot;,&quot;description&quot;:&quot;Onboarding content for Veeam-Hosted Services&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:162,&quot;isContainer&quot;:true,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[{&quot;id&quot;:177,&quot;type&quot;:0,&quot;title&quot;:&quot;Onboarding Toolkit for Veeam Data Cloud for Microsoft 365&quot;,&quot;description&quot;:&quot;Confidently protect Microsoft 365 with Veeam\u2019s cloud-native backup&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:184,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:1,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/onboarding-toolkit-for-veeam-data-cloud-for-microsoft-365-177&quot;},{&quot;id&quot;:185,&quot;type&quot;:0,&quot;title&quot;:&quot;Onboarding Toolkit for Veeam Data Cloud for Microsoft Entra ID&quot;,&quot;description&quot;:&quot;Confidently protect Microsoft Entra ID with Veeam\u2019s cloud-native backup&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:184,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:1,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/onboarding-toolkit-for-veeam-data-cloud-for-microsoft-entra-id-185&quot;},{&quot;id&quot;:186,&quot;type&quot;:0,&quot;title&quot;:&quot;Onboarding Toolkit for Veeam Data Cloud for Salesforce &quot;,&quot;description&quot;:&quot;Confidently protect Salesforce with Veeam\u2019s cloud-native backup&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:184,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:1,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/onboarding-toolkit-for-veeam-data-cloud-for-salesforce-186&quot;},{&quot;id&quot;:187,&quot;type&quot;:0,&quot;title&quot;:&quot;Onboarding Toolkit for Veeam Data Cloud Vault &quot;,&quot;description&quot;:&quot;Secure Cloud Storage Made Easy&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:184,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:1,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/onboarding-toolkit-for-veeam-data-cloud-vault-187&quot;}],&quot;visibleTopicsCount&quot;:4,&quot;containerCategoriesCount&quot;:0,&quot;contentCategoriesCount&quot;:4,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/veeam-hosted-services-184&quot;}],&quot;language&quot;:&quot;en&quot;,&quot;visibleTopicsCount&quot;:82,&quot;containerCategoriesCount&quot;:2,&quot;contentCategoriesCount&quot;:0,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/veeam-university-free-162&quot;},{&quot;id&quot;:166,&quot;type&quot;:0,&quot;title&quot;:&quot;Veeam Technical Specialist&quot;,&quot;description&quot;:&quot;Veeam Technical Specialist&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:null,&quot;isContainer&quot;:true,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[{&quot;id&quot;:167,&quot;type&quot;:0,&quot;title&quot;:&quot;Veeam Data Platform Fundamentals&quot;,&quot;description&quot;:&quot;Veeam Data Platform Fundamentals&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:166,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:35,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/veeam-data-platform-fundamentals-167&quot;},{&quot;id&quot;:168,&quot;type&quot;:0,&quot;title&quot;:&quot;SaaS Protection&quot;,&quot;description&quot;:&quot;SaaS Protection&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:166,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:15,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/saas-protection-168&quot;},{&quot;id&quot;:170,&quot;type&quot;:0,&quot;title&quot;:&quot;Cybersecurity&quot;,&quot;description&quot;:&quot;Cybersecurity&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:166,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:24,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/cybersecurity-170&quot;},{&quot;id&quot;:171,&quot;type&quot;:0,&quot;title&quot;:&quot;Public Cloud&quot;,&quot;description&quot;:&quot;Public Cloud&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:166,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:9,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/public-cloud-171&quot;},{&quot;id&quot;:173,&quot;type&quot;:0,&quot;title&quot;:&quot;Kubernetes Data Protection&quot;,&quot;description&quot;:&quot;Automate, protect, and recover Kubernetes workloads with Veeam Kasten.&quot;,&quot;thumbnailImage&quot;:null,&quot;parentId&quot;:166,&quot;isContainer&quot;:false,&quot;supportedContentTypes&quot;:[&quot;conversation&quot;,&quot;idea&quot;,&quot;question&quot;],&quot;children&quot;:[],&quot;visibleTopicsCount&quot;:9,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/kubernetes-data-protection-173&quot;}],&quot;language&quot;:&quot;en&quot;,&quot;visibleTopicsCount&quot;:92,&quot;containerCategoriesCount&quot;:0,&quot;contentCategoriesCount&quot;:5,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/veeam-technical-specialist-166&quot;}],&quot;knowledgeBaseCategoriesV2&quot;:[],&quot;communityCustomerTitle&quot;:&quot;veeam-en&quot;,&quot;ssoLoginUrl&quot;:&quot;https:\/\/community.veeam.com\/ssoproxy\/login?ssoType=openidconnect&quot;,&quot;showAuthPage&quot;:false,&quot;items&quot;:[{&quot;key&quot;:&quot;knowledgeBase&quot;,&quot;visibility&quot;:false,&quot;name&quot;:&quot;Knowledge Base&quot;},{&quot;key&quot;:&quot;community&quot;,&quot;visibility&quot;:true,&quot;name&quot;:&quot;Community&quot;},{&quot;key&quot;:&quot;ideation&quot;,&quot;visibility&quot;:true,&quot;name&quot;:&quot;Ideas&quot;,&quot;url&quot;:&quot;\/ideas&quot;},{&quot;key&quot;:&quot;event&quot;,&quot;visibility&quot;:true,&quot;name&quot;:&quot;Events&quot;,&quot;url&quot;:&quot;\/events&quot;},{&quot;key&quot;:&quot;group&quot;,&quot;visibility&quot;:true,&quot;name&quot;:&quot;Groups&quot;,&quot;url&quot;:&quot;\/groups&quot;},{&quot;key&quot;:&quot;productUpdates&quot;,&quot;name&quot;:&quot;Product Updates&quot;,&quot;visibility&quot;:true,&quot;url&quot;:&quot;\/product-updates&quot;},{&quot;key&quot;:&quot;custom&quot;,&quot;visibility&quot;:false,&quot;name&quot;:&quot;Kubernetes Korner&quot;,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/groups\/kubernetes-korner-90&quot;,&quot;external&quot;:false},{&quot;key&quot;:&quot;custom&quot;,&quot;name&quot;:&quot;Leaderboard&quot;,&quot;visibility&quot;:true,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/leaderboard&quot;},{&quot;key&quot;:&quot;custom&quot;,&quot;visibility&quot;:false,&quot;name&quot;:&quot;VeeamON Events&quot;,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/p\/VeeamON2024&quot;,&quot;external&quot;:false},{&quot;key&quot;:&quot;custom&quot;,&quot;visibility&quot;:false,&quot;name&quot;:&quot;Veeam 100 Directory &quot;,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/p\/veeam100directory&quot;,&quot;external&quot;:true},{&quot;key&quot;:&quot;custom&quot;,&quot;visibility&quot;:false,&quot;name&quot;:&quot;Events&quot;,&quot;url&quot;:&quot;https:\/\/community.veeam.com\/events?tab=upcoming&quot;,&quot;external&quot;:false}],&quot;searchInfo&quot;:{&quot;isFederatedSalesforceSearch&quot;:false,&quot;isFederatedSkilljarSearch&quot;:false,&quot;isFederatedFreshdeskSearch&quot;:false,&quot;category&quot;:null,&quot;isParentCategory&quot;:null,&quot;isExtendableSearch&quot;:null},&quot;permissions&quot;:{&quot;ideation&quot;:false,&quot;productUpdates&quot;:true},&quot;enabledLanguages&quot;:[{&quot;id&quot;:&quot;065312c1-caa0-70d0-8000-d4ea4d20df08&quot;,&quot;code&quot;:&quot;fr&quot;,&quot;iso&quot;:&quot;fr&quot;,&quot;locale&quot;:&quot;fr_FR&quot;,&quot;name&quot;:&quot;French&quot;,&quot;isEnabled&quot;:true,&quot;isDefault&quot;:false,&quot;isPublished&quot;:false},{&quot;id&quot;:&quot;065312c1-ca91-735e-8000-b2b2e2c170ab&quot;,&quot;code&quot;:&quot;de&quot;,&quot;iso&quot;:&quot;de&quot;,&quot;locale&quot;:&quot;de_DE&quot;,&quot;name&quot;:&quot;German (Germany)&quot;,&quot;isEnabled&quot;:true,&quot;isDefault&quot;:false,&quot;isPublished&quot;:false},{&quot;id&quot;:&quot;065312c1-cc7a-7d85-8000-2a057a892d0b&quot;,&quot;code&quot;:&quot;it&quot;,&quot;iso&quot;:&quot;it&quot;,&quot;locale&quot;:&quot;it_IT&quot;,&quot;name&quot;:&quot;Italian&quot;,&quot;isEnabled&quot;:true,&quot;isDefault&quot;:false,&quot;isPublished&quot;:false},{&quot;id&quot;:&quot;065312c1-cabd-7205-8000-fe0b7fa72b79&quot;,&quot;code&quot;:&quot;br&quot;,&quot;iso&quot;:&quot;pt-br&quot;,&quot;locale&quot;:&quot;pt_BR&quot;,&quot;name&quot;:&quot;Portuguese (Brazil)&quot;,&quot;isEnabled&quot;:true,&quot;isDefault&quot;:false,&quot;isPublished&quot;:false},{&quot;id&quot;:&quot;065312c1-cb68-7a4b-8000-2cb70f6ba19f&quot;,&quot;code&quot;:&quot;es&quot;,&quot;iso&quot;:&quot;es&quot;,&quot;locale&quot;:&quot;es_ES&quot;,&quot;name&quot;:&quot;Spanish&quot;,&quot;isEnabled&quot;:true,&quot;isDefault&quot;:false,&quot;isPublished&quot;:false}],&quot;publishedLanguages&quot;:[{&quot;id&quot;:&quot;065312c1-c9f0-72ed-8000-5cad0147517b&quot;,&quot;code&quot;:&quot;en&quot;,&quot;iso&quot;:&quot;en-us&quot;,&quot;locale&quot;:&quot;en_US&quot;,&quot;name&quot;:&quot;English&quot;,&quot;isEnabled&quot;:true,&quot;isDefault&quot;:true,&quot;isPublished&quot;:true}],&quot;selectedLanguage&quot;:&quot;en&quot;,&quot;isSpacesOnly&quot;:false,&quot;phrases&quot;:{&quot;Common&quot;:{&quot;main.navigation.menu_label&quot;:&quot;Menu&quot;,&quot;nav.title.forum.overview&quot;:&quot;Community overview&quot;,&quot;nav.title.forum.recent.activity&quot;:&quot;Recently active topics&quot;,&quot;nav.title.forum.activity.last.visit&quot;:&quot;Active since last visit&quot;,&quot;nav.title.forum.unanswered.questions&quot;:&quot;Unanswered questions&quot;,&quot;bb.spoiler.show-content&quot;:&quot;Show content&quot;,&quot;bb.spoiler.hide-content&quot;:&quot;Hide content&quot;,&quot;wrote&quot;:&quot;wrote&quot;,&quot;js.attachments.place_in_text&quot;:&quot;Place in text&quot;,&quot;js.attachments.show_as_attachment&quot;:&quot;Show as attachment&quot;,&quot;js.attachments.delete&quot;:&quot;Delete&quot;,&quot;js.uploader.error_file_type&quot;:&quot;Sorry, we couldn't upload your file because we don't support that file type. Supported file types: {allowed_files_type}&quot;,&quot;js.uploader.error_file_size&quot;:&quot;Sorry, we couldn\u2019t upload your file because it's too big. Maximum file size: {allowed_files_size}&quot;,&quot;content_type.label.idea&quot;:&quot;Idea&quot;,&quot;js.uploader.error_on_upload&quot;:&quot;Something went wrong, please check your link and try again.&quot;},&quot;Forum&quot;:{&quot;nav.title.knowledgebase&quot;:&quot;Knowledge base&quot;,&quot;nav.title.knowledgebase.overview&quot;:&quot;Knowledge base&quot;,&quot;nav.title.community&quot;:&quot;Community&quot;,&quot;live.search.placeholder&quot;:&quot;Search...&quot;,&quot;live.search.search.text&quot;:&quot;Search:&quot;,&quot;live.search.no.result.found.text&quot;:&quot;No results found for:&quot;,&quot;live.search.trending.text&quot;:&quot;Trending&quot;,&quot;live.search.ask.question&quot;:&quot;Ask question to the community&quot;,&quot;live.search.view.all&quot;:&quot;View all&quot;,&quot;topic.form.type.discussion.label&quot;:&quot;Content&quot;,&quot;content_type.label.article&quot;:&quot;Article&quot;,&quot;content_type.label.question&quot;:&quot;Question&quot;,&quot;answered.mark.title&quot;:&quot;Solved&quot;,&quot;ask.question.title&quot;:&quot;Ask question&quot;,&quot;ask.question.title.description&quot;:&quot;Start your question with 'What', 'How' etc and phrase it like a question.&quot;,&quot;ask.question.optional.description&quot;:&quot;Add description (optional)&quot;,&quot;cancel&quot;:&quot;Cancel&quot;,&quot;create&quot;:&quot;Create&quot;,&quot;title&quot;:&quot;Title&quot;,&quot;Choose your subject&quot;:&quot;Choose your category&quot;,&quot;post.textarea.label&quot;:&quot;Description&quot;,&quot;topic.editor.subforum.title&quot;:&quot;Category&quot;,&quot;topic.first.reply.placeholder.textarea&quot;:&quot;Add as many details as possible, by providing details you\u2019ll make it easier for others to reply&quot;,&quot;wysiwyg.h1.btn.title&quot;:&quot;Large heading&quot;,&quot;wysiwyg.h3.btn.title&quot;:&quot;Small heading&quot;,&quot;wysiwyg.embed.btn.title&quot;:&quot;Embed media&quot;,&quot;wysiwyg.video_embed.btn.title&quot;:&quot;Video embed&quot;,&quot;Save&quot;:&quot;Save&quot;,&quot;Cancel&quot;:&quot;Cancel&quot;,&quot;wysiwyg.submenu.title&quot;:&quot;More options&quot;,&quot;wysiwyg.features.links.text_input&quot;:&quot;Text&quot;,&quot;wysiwyg.features.links.link_input&quot;:&quot;URL&quot;,&quot;wysiwyg.features.links.link_input.placeholder&quot;:&quot;Paste a link&quot;,&quot;wysiwyg.modals.embed.title&quot;:&quot;Embed media&quot;,&quot;wysiwyg.modals.embed.placeholder&quot;:&quot;Paste a link to embed media. Supported platforms: YouTube, Soundcloud, Deezer, Vimeo, Dailymotion.&quot;,&quot;wysiwyg.modals.embed.submit&quot;:&quot;Insert&quot;,&quot;wysiwyg.features.links.link_button&quot;:&quot;Save&quot;,&quot;Upload image&quot;:&quot;Upload image&quot;,&quot;o_embed.error.error_no_url&quot;:&quot;Missing embed URL&quot;,&quot;o_embed.error.error_not_valid_url&quot;:&quot;URL provided is not valid&quot;,&quot;o_embed.error.error_service_not_supported&quot;:&quot;The provided domain is not supported&quot;,&quot;o_embed.error.error_not_retrieved&quot;:&quot;Embed data could not be retrieved&quot;,&quot;go.to.homepage&quot;:&quot;Go to homepage&quot;,&quot;My profile&quot;:&quot;My profile&quot;,&quot;Topic|Topics&quot;:&quot;Topic|Topics&quot;,&quot;Reply|Replies&quot;:&quot;Comment|Comments&quot;,&quot;Solved&quot;:&quot;Solved&quot;,&quot;header.profile.dropdown.subscriptions&quot;:&quot;Subscriptions&quot;,&quot;Private messages&quot;:&quot;Private messages&quot;,&quot;Settings&quot;:&quot;Settings&quot;,&quot;Logout&quot;:&quot;Log out&quot;},&quot;Control&quot;:{&quot;editor.controls.quote&quot;:&quot;Quote&quot;,&quot;editor.controls.spoiler&quot;:&quot;Spoiler&quot;,&quot;editor.controls.code&quot;:&quot;Code&quot;,&quot;editor.controls.url&quot;:&quot;Url&quot;}},&quot;searchRevamp&quot;:true,&quot;aiSearchSummary&quot;:false,&quot;selectedTemplate&quot;:0}"><section class="main-navigation--wrapper header-navigation"><div class="main-navigation-sitewidth"><div class="header-navigation_logo-wrapper"><a target="_self" href="/" aria-label="Forum|go.to.homepage" class="header-navigation_logo-anchor" track="[object Object]"><img class="header-navigation_logo" src="https://uploads-eu-west-1.insided.com/veeam-en/attachment/e0f13e7d-e6fd-4e9b-9826-586dfcab9b54.png" alt="veeam-en Logo" /></a></div><div class="header-navigation-items-wrapper"><div class="header-navigation-items_and_search"><div class="header-navigation-items_and_search-inner"><nav role="navigation"><ul class="header-navigation-items_menu"><li class="header-navigation_list-item main-menu" track="[object Object]"><div class="dropdown-container"><button id="community-categories" aria-haspopup="true" type="button" style="background: none; border: none; font-weight: inherit; display: inline-block; padding: 0px; margin: 0px; cursor: pointer;"> <span style="display: flex; align-items: center;" class="main-menu-trigger"><span>Community</span><svg aria-hidden="true" width="16" height="16" class viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M7.41 8.58997L12 13.17L16.59 8.58997L18 9.99997L12 16L6 9.99997L7.41 8.58997Z" fill="currentColor"></path></svg></span></button><ul aria-labelledby="community-categories" Component="ul" tabIndex="-1" role="menu" class="dropdown dropdown--forums-overview is-hidden"><li aria-hidden="true" class="arrow is-hidden-S"></li><li class="main-menu-list--overflow-scroll"><ul class="main-menu-list main-menu-list--quicklinks"><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-0" role="option"><a track="[object Object]" href="/" class="main-menu-link link--text"><span>Community overview</span></a></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-1" role="option"><a track="[object Object]" href="/activity/recent" class="main-menu-link link--text"><span>Recently active topics</span></a></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-2" role="option"><a track="[object Object]" href="/activity/unanswered" class="main-menu-link link--text"><span>Unanswered questions</span></a></li></ul><ul class="main-menu-list"><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-3" role="option"><div><a id="mega-menu-category-40" track="[object Object]" href="https://community.veeam.com/community-40" title="Community" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name"><strong>Community</strong></span><span class="text--meta"></span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-4" role="option"><div><a id="mega-menu-category-56" track="[object Object]" href="https://community.veeam.com/news-56" title="News" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">News</span><span class="text--meta">263</span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-5" role="option"><div><a id="mega-menu-category-58" track="[object Object]" href="https://community.veeam.com/general-information-58" title="General Information" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">General Information</span><span class="text--meta">8</span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-6" role="option"><div><a id="mega-menu-category-57" track="[object Object]" href="https://community.veeam.com/blogs-and-podcasts-57" title="Blogs and Podcasts" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Blogs and Podcasts</span><span class="text--meta">1400</span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-7" role="option"><div><a id="mega-menu-category-67" track="[object Object]" href="https://community.veeam.com/yara-and-script-library-67" title="YARA and Script Library" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">YARA and Script Library</span><span class="text--meta">179</span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-8" role="option"><div><a id="mega-menu-category-66" track="[object Object]" href="https://community.veeam.com/discussion-boards-66" title="Discussion Boards" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Discussion Boards</span><span class="text--meta">3463</span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-9" role="option"><div><a id="mega-menu-category-141" track="[object Object]" href="https://community.veeam.com/veeamon-events-141" title="VeeamON Events" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">VeeamON Events</span><span class="text--meta">32</span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-10" role="option"><div><a id="mega-menu-category-126" track="[object Object]" href="https://community.veeam.com/security-blueprints-126" title="Security Blueprints" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name"><strong>Security Blueprints</strong></span><span class="text--meta"></span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-11" role="option"><div><a id="mega-menu-category-127" track="[object Object]" href="https://community.veeam.com/veeam-backup-replication-127" title="Veeam Backup &amp; Replication" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Veeam Backup &amp; Replication</span><span class="text--meta">38</span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-12" role="option"><div><a id="mega-menu-category-128" track="[object Object]" href="https://community.veeam.com/cloud-backup-128" title="Cloud Backup " target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Cloud Backup </span><span class="text--meta">6</span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-13" role="option"><div><a id="mega-menu-category-130" track="[object Object]" href="https://community.veeam.com/monitoring-130" title="Monitoring" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Monitoring</span><span class="text--meta">3</span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-14" role="option"><div><a id="mega-menu-category-131" track="[object Object]" href="https://community.veeam.com/saas-131" title="SaaS" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">SaaS</span><span class="text--meta">3</span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-15" role="option"><div><a id="mega-menu-category-132" track="[object Object]" href="https://community.veeam.com/kasten-132" title="Kasten" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Kasten</span><span class="text--meta">3</span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-16" role="option"><div><a id="mega-menu-category-133" track="[object Object]" href="https://community.veeam.com/databases-133" title="Databases" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Databases</span><span class="text--meta">3</span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-17" role="option"><div><a id="mega-menu-category-150" track="[object Object]" href="https://community.veeam.com/alliance-vendor-150" title="Alliance Vendor" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Alliance Vendor</span><span class="text--meta">23</span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-18" role="option"><div><a id="mega-menu-category-182" track="[object Object]" href="https://community.veeam.com/veeam-data-cloud-182" title="Veeam Data Cloud" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Veeam Data Cloud</span><span class="text--meta">9</span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-19" role="option"><div><a id="mega-menu-category-162" track="[object Object]" href="https://community.veeam.com/veeam-university-free-162" title="Veeam University FREE" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name"><strong>Veeam University FREE</strong></span><span class="text--meta"></span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-20" role="option"><div class="dropdown-container"><button id="community-categories-183" aria-haspopup="true" type="button" style="background: none; border: none; font-weight: inherit; display: inline-block; padding: 0px; margin: 0px; cursor: pointer;"> <div><a id="mega-menu-category-183" track="[object Object]" href="https://community.veeam.com/self-managed-deployment-183" title="Self-Managed Deployment" target rel class="link--text main-menu-link main-menu-link--category main-menu-link--category--nested"><span class="main-menu-link__name">Self-Managed Deployment</span><svg width="16" height="16" viewBox="0 0 24 24" class><path d="M10 6L8.59003 7.41L13.17 12L8.59003 16.59L10 18L16 12L10 6Z" fill="currentColor"></path></svg></a></div></button><ul aria-labelledby="community-categories-183" Component="ul" tabIndex="-1" role="menu" class="dropdown--forums-overview--nested is-hidden"><li class="dropdown dropdown--forums-overview main-menu-list--overflow-scroll" id="mega-menu-category-dropdown-183"><ul class="main-menu-list"><li class="main-menu-list__item" id="downshift-7767-item-28" role="option"><a track="[object Object]" href="https://community.veeam.com/onboarding-for-veeam-data-platform-163" title="Onboarding for Veeam Data Platform" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Onboarding for Veeam Data Platform</span><span class="text--meta">45</span></a></li><li class="main-menu-list__item" id="downshift-7767-item-29" role="option"><a track="[object Object]" href="https://community.veeam.com/onboarding-for-veeam-recovery-orchestrator-175" title="Onboarding for Veeam Recovery Orchestrator" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Onboarding for Veeam Recovery Orchestrator</span><span class="text--meta">9</span></a></li><li class="main-menu-list__item" id="downshift-7767-item-30" role="option"><a track="[object Object]" href="https://community.veeam.com/onboarding-for-veeam-backup-for-microsoft-365-176" title="Onboarding for Veeam Backup for Microsoft 365" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Onboarding for Veeam Backup for Microsoft 365</span><span class="text--meta">15</span></a></li><li class="main-menu-list__item" id="downshift-7767-item-31" role="option"><a track="[object Object]" href="https://community.veeam.com/onboarding-for-veeam-kasten-for-kubernetes-179" title=" Onboarding for Veeam Kasten for Kubernetes" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name"> Onboarding for Veeam Kasten for Kubernetes</span><span class="text--meta">9</span></a></li></ul></li></ul></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-21" role="option"><div class="dropdown-container"><button id="community-categories-184" aria-haspopup="true" type="button" style="background: none; border: none; font-weight: inherit; display: inline-block; padding: 0px; margin: 0px; cursor: pointer;"> <div><a id="mega-menu-category-184" track="[object Object]" href="https://community.veeam.com/veeam-hosted-services-184" title="Veeam-Hosted Services" target rel class="link--text main-menu-link main-menu-link--category main-menu-link--category--nested"><span class="main-menu-link__name">Veeam-Hosted Services</span><svg width="16" height="16" viewBox="0 0 24 24" class><path d="M10 6L8.59003 7.41L13.17 12L8.59003 16.59L10 18L16 12L10 6Z" fill="currentColor"></path></svg></a></div></button><ul aria-labelledby="community-categories-184" Component="ul" tabIndex="-1" role="menu" class="dropdown--forums-overview--nested is-hidden"><li class="dropdown dropdown--forums-overview main-menu-list--overflow-scroll" id="mega-menu-category-dropdown-184"><ul class="main-menu-list"><li class="main-menu-list__item" id="downshift-7767-item-28" role="option"><a track="[object Object]" href="https://community.veeam.com/onboarding-toolkit-for-veeam-data-cloud-for-microsoft-365-177" title="Onboarding Toolkit for Veeam Data Cloud for Microsoft 365" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Onboarding Toolkit for Veeam Data Cloud for Microsoft 365</span><span class="text--meta">1</span></a></li><li class="main-menu-list__item" id="downshift-7767-item-29" role="option"><a track="[object Object]" href="https://community.veeam.com/onboarding-toolkit-for-veeam-data-cloud-for-microsoft-entra-id-185" title="Onboarding Toolkit for Veeam Data Cloud for Microsoft Entra ID" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Onboarding Toolkit for Veeam Data Cloud for Microsoft Entra ID</span><span class="text--meta">1</span></a></li><li class="main-menu-list__item" id="downshift-7767-item-30" role="option"><a track="[object Object]" href="https://community.veeam.com/onboarding-toolkit-for-veeam-data-cloud-for-salesforce-186" title="Onboarding Toolkit for Veeam Data Cloud for Salesforce " target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Onboarding Toolkit for Veeam Data Cloud for Salesforce </span><span class="text--meta">1</span></a></li><li class="main-menu-list__item" id="downshift-7767-item-31" role="option"><a track="[object Object]" href="https://community.veeam.com/onboarding-toolkit-for-veeam-data-cloud-vault-187" title="Onboarding Toolkit for Veeam Data Cloud Vault " target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Onboarding Toolkit for Veeam Data Cloud Vault </span><span class="text--meta">1</span></a></li></ul></li></ul></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-22" role="option"><div><a id="mega-menu-category-166" track="[object Object]" href="https://community.veeam.com/veeam-technical-specialist-166" title="Veeam Technical Specialist" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name"><strong>Veeam Technical Specialist</strong></span><span class="text--meta"></span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-23" role="option"><div><a id="mega-menu-category-167" track="[object Object]" href="https://community.veeam.com/veeam-data-platform-fundamentals-167" title="Veeam Data Platform Fundamentals" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Veeam Data Platform Fundamentals</span><span class="text--meta">35</span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-24" role="option"><div><a id="mega-menu-category-168" track="[object Object]" href="https://community.veeam.com/saas-protection-168" title="SaaS Protection" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">SaaS Protection</span><span class="text--meta">15</span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-25" role="option"><div><a id="mega-menu-category-170" track="[object Object]" href="https://community.veeam.com/cybersecurity-170" title="Cybersecurity" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Cybersecurity</span><span class="text--meta">24</span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-26" role="option"><div><a id="mega-menu-category-171" track="[object Object]" href="https://community.veeam.com/public-cloud-171" title="Public Cloud" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Public Cloud</span><span class="text--meta">9</span></a></div></li><li class="main-menu-list__item main-menu-list__item--no-hover" id="downshift-7767-item-27" role="option"><div><a id="mega-menu-category-173" track="[object Object]" href="https://community.veeam.com/kubernetes-data-protection-173" title="Kubernetes Data Protection" target rel class="link--text main-menu-link main-menu-link--category"><span class="main-menu-link__name">Kubernetes Data Protection</span><span class="text--meta">9</span></a></div></li></ul></li></ul></div></li><li class="header-navigation_list-item"><a track="[object Object]" class="header-navigation_link title-events" href="/events" target rel>Events</a></li><li class="header-navigation_list-item"><a track="[object Object]" class="header-navigation_link title-groups" href="/groups" target rel>Groups</a></li><li class="header-navigation_list-item"><a track="[object Object]" class="header-navigation_link title-product-updates" href="/product-updates" target rel>Product Updates</a></li><li class="header-navigation_list-item"><a track="[object Object]" class="header-navigation_link title-leaderboard" href="https://community.veeam.com/leaderboard" target rel>Leaderboard</a></li></ul></nav><div class="header-navigation-items_hamburger"><div class="slider-menu"><span class="slider-trigger" role="button" tabIndex="0"><svg width="24" height="24" viewBox="0 0 24 24" fill="none"><path d="M3 18H21V16H3V18ZM3 13H21V11H3V13ZM3 6V8H21V6H3Z" fill="currentColor"></path></svg></span></div></div><div class="header-navigation_logo-wrapper is-hidden-L"><a target="_self" href="/" aria-label="Forum|go.to.homepage" class="header-navigation_logo-anchor" track="[object Object]"><img class="header-navigation_logo" src="https://uploads-eu-west-1.insided.com/veeam-en/attachment/e0f13e7d-e6fd-4e9b-9826-586dfcab9b54.png" alt="veeam-en Logo" /></a></div></div></div></div><section class="main-navigation--nav-buttons-wrapper" data-view="MainNavigation"><ul><li class="main-navigation--language-switcher"><div><div class="main-navigation--language-switcher_selected" tabIndex="0" role="button"><div class="main-navigation--language-switcher_language-icon main-navigation--language-switcher_language-icon--en"></div><span>EN</span></div></div></li><li class="is-hidden-S"><a href="/topic/new" data-track="{&quot;trigger&quot;:&quot;navigation&quot;,&quot;type&quot;:&quot;Topic Initiated&quot;}" data-ga-track="{&quot;eventCategory&quot;:&quot;Homepage&quot;,&quot;eventAction&quot;:&quot;Create topic clicked&quot;,&quot;eventLabel&quot;:{&quot;Position&quot;:&quot;Navigation&quot;}}" class="menu-create-topic qa-menu-create-topic btn btn--cta" role="button" title><span aria-hidden="true" class="header-navigation-button-icon"><svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg" class><path d="M19 13H13V19H11V13H5V11H11V5H13V11H19V13Z"></path></svg></span><span></span></a></li><li><a role="button" href="https://community.veeam.com/ssoproxy/login?ssoType=openidconnect" class="header-login-button qa-header-login-button btn btn--secondary"><span aria-hidden="true" class="header-navigation-button-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M12 12C14.21 12 16 10.21 16 8C16 5.79 14.21 4 12 4C9.79 4 8 5.79 8 8C8 10.21 9.79 12 12 12ZM12 14C9.33 14 4 15.34 4 18V20H20V18C20 15.34 14.67 14 12 14Z" fill="currentColor"></path></svg></span><span></span></a></li></ul></section></div></section></div>                                                            
                                                                                                                                                <div data-preact="topic-banner/TopicBanner" class="widget--notification qa-widget-notification custom-notification" data-props="{&quot;serverSideProps&quot;:{&quot;topicIds&quot;:[{&quot;id&quot;:10321,&quot;title&quot;:&quot;Veeam Data Platform v13 Upgrade Center&quot;,&quot;url&quot;:&quot;\/topic\/show?tid=10321&amp;fid=57&quot;,&quot;type&quot;:&quot;article&quot;}]},&quot;selectedTopic&quot;:{&quot;url&quot;:&quot;https:\/\/community.veeam.com\/blogs-and-podcasts-57\/veeam-data-platform-v13-upgrade-center-10321&quot;,&quot;title&quot;:&quot;Veeam Data Platform v13 Upgrade Center&quot;,&quot;description&quot;:&quot;&lt;p&gt;Welcome to the V13 Upgrade Center, which will guide you through the process of this launch. For\u00a0&lt;strong&gt;V13,\u00a0&lt;\/strong&gt;some new improved availability and accelerations are in play; so this release will be one customers and partners should pay close attention to. The most important thing right from the top that we will start with for this one is current status and last update:&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Current Status: &lt;\/strong&gt;Veeam Software Appliance in Early Release&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;section class=\&quot;callout callout-blue\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Last Updated:\u00a0\u00a0&lt;\/strong&gt;4-September 2025&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;Before we dive into specifics and advice, it is important to orientate ourselves on where we are with this release. I\u2019ve prepared this&lt;strong&gt; Frequently Asked Questions&lt;\/strong&gt; list to get this started:&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;p&gt;&lt;strong&gt;Early Release FAQ\u00a0&lt;\/strong&gt;This section will deprecate in Q4 2025 - Updated 4-September 2025&lt;\/p&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;ul&gt;&lt;li&gt;&lt;strong&gt;Can I migrate from Veeam Backup &amp;amp; Replication 12.3 to the Veeam Software Appliance?\u00a0&lt;\/strong&gt;Not yet, but this will be available in a subsequent release.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;I just want to upgrade Veeam Backup &amp;amp; Replication on Windows, can I do that?\u00a0&lt;\/strong&gt;Not yet, but this will be available in a subsequent release.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;What is an Early Release?&lt;\/strong&gt;\u00a0This is a release that is simply early. This is a few months ahead of a full-fledged V13 release.\u00a0&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;Is the Early Release supported?\u00a0&lt;\/strong&gt;Yes, for active support contracts.\u00a0&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;What is the Veeam Software Appliance?\u00a0&lt;\/strong&gt;This is the pre-built, pre-hardened and predictable environment to run Veeam. This early release includes Veeam Backup &amp;amp; Replication 13.0.0 and additional appliances can be scaled out to run roles like proxies, repositories, mount servers and more. You may see it referred to as VSA here, from the Veeam team or in the Forums.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;What is the Early Release status suited for?&lt;\/strong&gt;\u00a0The Early Release of the Veeam Software Appliance is suited ideally for net-new deployments (i.e. environments that do not upgrade). Other use cases include advanced users with labs that are production-level to get a good feel for the Veeam Software Appliance.\u00a0&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;Are storage plug-ins ready for the Veeam Software Appliance during this Early Release status?&lt;\/strong&gt; Some of them are, this should be a consideration before deploying during the Early Release stage for net-new deployments, especially if routine other deployments in your organization have planned on the storage integrations.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;What about the Configuration Backup, can I use that to move to the Veeam Software Appliance?&lt;\/strong&gt; This is not offered at this time, the Veeam Software Appliance in Early Release Status is intended for net-new deployments.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;Where do I download the Veeam Software Appliance?&lt;\/strong&gt; The early release status is downloaded from the&lt;a href=\&quot;https:\/\/www.veeam.com\/products\/data-platform-trial-download.html?tab=vsa-download\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;&lt;strong&gt; Veeam website here&lt;\/strong&gt;&lt;\/a&gt;\u00a0(or from My Account). Be sure to click the \u2018tab\u2019 for the right mode:\t&lt;figure&gt;&lt;img alt=\&quot;\&quot; src=\&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/adf78e81-5092-4f4b-9c79-6e13f86a9787.png\&quot; \/&gt;&lt;\/figure&gt;&lt;p&gt;\u00a0&lt;\/p&gt;\t&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;Where can I get more information on this release? &lt;\/strong&gt;This &lt;a href=\&quot;https:\/\/forums.veeam.com\/veeam-backup-replication-f2\/frequently-asked-questions-release-schedule-and-deployment-options-t99995.html\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;&lt;strong&gt;Forum post&lt;\/strong&gt; &lt;\/a&gt;does a great job of overviewing the current status, &lt;a href=\&quot;https:\/\/forums.veeam.com\/veeam-backup-replication-f2\/current-version-t9456.html\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;&lt;strong&gt;current build information&lt;\/strong&gt;&lt;\/a&gt;, the &lt;strong&gt;&lt;a href=\&quot;https:\/\/www.veeam.com\/kb4738\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;Release Information KB&lt;\/a&gt;&lt;\/strong&gt;, the\u00a0&lt;a href=\&quot;https:\/\/www.veeam.com\/veeam_backup_13_whats_new__wn.pdf\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;&lt;strong&gt;What\u2019s New Document&lt;\/strong&gt;&lt;\/a&gt;, the &lt;strong&gt;&lt;a href=\&quot;https:\/\/helpcenter.veeam.com\/rn\/veeam_backup_13_release_notes.html#system-requirements-\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Release Notes&lt;\/a&gt;&lt;\/strong&gt;\u00a0as well as the whole of the\u00a0&lt;strong&gt;&lt;a href=\&quot;https:\/\/helpcenter.veeam.com\/\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Veeam Help Center.&lt;\/a&gt;&lt;\/strong&gt;&lt;\/li&gt;&lt;\/ul&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;p&gt;&lt;strong&gt;Overall FAQ&lt;\/strong&gt;: This section will persist past the Early Release stage - Updated 4-September 2025&lt;\/p&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;ul&gt;&lt;li&gt;&lt;strong&gt;What is the difference between\u00a0&lt;span style=\&quot;color:#16a085;\&quot;&gt;&lt;em&gt;migrate\u00a0&lt;\/em&gt;&lt;\/span&gt;and\u00a0&lt;span style=\&quot;color:#16a085;\&quot;&gt;&lt;em&gt;upgrade&lt;\/em&gt;\u00a0&lt;\/span&gt;for V13 of Veeam Backup &amp;amp; Replication?\u00a0&lt;\/strong&gt;A\u00a0&lt;span style=\&quot;color:#16a085;\&quot;&gt;&lt;em&gt;migration\u00a0&lt;\/em&gt;&lt;\/span&gt;will be going from Veeam Backup &amp;amp; Replication on Windows to the Veeam Software Appliance (changed environment). An\u00a0&lt;span style=\&quot;color:#16a085;\&quot;&gt;&lt;em&gt;upgrade\u00a0&lt;\/em&gt;&lt;\/span&gt;would be going from Veeam Backup &amp;amp; Replication V12.3 on Windows to Veeam Backup &amp;amp; Replication V13 on Windows (same environment). The Early Release does not offer either of these (this will change). If you are interested in migration to the Veeam Software Appliance with\u00a0conversion assistance and expert guidance, sign up for the\u00a0&lt;a href=\&quot;https:\/\/go.veeam.com\/vsa-conversion\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;Transition to the Veeam Software Appliance&lt;\/a&gt;\u00a0page.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;For Veeam Software Appliance deployments, what is different?\u00a0&lt;\/strong&gt;Generally speaking, the code and capabilities across Veeam Backup &amp;amp; Replication version 13 whether provided from the Veeam Sofware Appliance or installed on Windows will have a consistent set of capabilities, but there are differences to note:&lt;\/li&gt;&lt;\/ul&gt;&lt;table&gt;&lt;tbody&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;&lt;span style=\&quot;color:#16a085;\&quot;&gt;Characteristic&lt;\/span&gt;&lt;\/strong&gt;&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;&lt;strong&gt;&lt;span style=\&quot;color:#16a085;\&quot;&gt;Veeam Backup &amp;amp; Replication V13 on the Veeam Software Appliance &lt;\/span&gt;&lt;\/strong&gt;(in early release status)&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;&lt;strong&gt;&lt;span style=\&quot;color:#16a085;\&quot;&gt;Veeam Backup &amp;amp; Replication V13\u00a0on Windows &lt;\/span&gt;&lt;\/strong&gt;(not yet available)&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;Deployment&lt;\/strong&gt;&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;OVA or ISO will build the Veeam Backup &amp;amp; Replication (or a plain Just Enough OS for other roles) system.&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;ISO would mount and install application on a Windows system with user choices, database configuration, file and folder paths, account setup and more.&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;New capabilities&lt;\/strong&gt;&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;Same as V13 on Windows, except the following:&lt;br \/&gt;\t\t\t-High Availability will only function on the Veeam Software Appliance.&lt;br \/&gt;\t\t\t-The appliance management interface will only function on the Veeam Software Appliance.&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;\t\t\t&lt;p&gt;All V13 capabilities &lt;em&gt;except &lt;\/em&gt;what is noted on the other side.&lt;\/p&gt;\t\t\t&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;Planned dates (targets)&lt;\/strong&gt;&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;Early released on 3-September 2025&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;General availability for Veeam Data Platform is planned for Q4 2025 as installable&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;&lt;span style=\&quot;color:#3498db;\&quot;&gt;IMPORTANT:&lt;\/span&gt;&lt;\/strong&gt;&lt;br \/&gt;\t\t\tLicensing Models used&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;Veeam Universal License, Rental License, NFR&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;Veeam Universal License, Rental License, NFR, Socket-Based License, Community Edition&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;\/tbody&gt;&lt;\/table&gt;&lt;p&gt;\u00a0&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Deprecated Capabilities and Discontinued Features: &lt;span style=\&quot;color:#3498db;\&quot;&gt;Now &lt;\/span&gt;is the time to prepare&lt;\/strong&gt;&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;One of the important things I want to highlight came earlier this year as a number of deprecated and discontinued features have been shared. This makes now a very good time to focus on the\u00a0&lt;em&gt;non-net-new\u00a0&lt;\/em&gt;deployments to ensure that any deprecated capabilities or discontinued features are mitigated. See this post from earlier in the year:&lt;br \/&gt;\u00a0&lt;\/p&gt;&lt;p&gt;&lt;oembed url=\&quot;https:\/\/community.veeam.com\/blogs-and-podcasts-57\/via-veeam-forums-v13-deprecated-and-discontinued-features-for-our-2025-release-9494\&quot;&gt;&lt;\/oembed&gt;&lt;\/p&gt;&lt;p&gt;Please read through the above, noting the two Forum links, but the top ones that I see that would be a good topic to address now are:&lt;\/p&gt;&lt;ul&gt;&lt;li&gt;VBR: Deprecated reversed incremental backup mode.&lt;\/li&gt;\t&lt;li&gt;VBR: Configurations with backup jobs having backup metadata still not upgraded to V12 format (upgrades when they are productized will be blocked if not) - see\u00a0&lt;a href=\&quot;https:\/\/forums.veeam.com\/veeam-backup-replication-f2\/best-way-to-update-legacy-vmware-backup-copy-jobs-to-the-new-v12-standard-t85038.html\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;[V12] Best way to update Legacy VMWare Backup Copy jobs to the new V12 standard?&lt;\/a&gt;\u00a0and\u00a0&lt;a href=\&quot;https:\/\/helpcenter.veeam.com\/docs\/backup\/powershell\/convert-vbrlegacycopybackup.html?ver=120\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Convert-VBRLegacyCopyBackup - Veeam Backup PowerShell Reference&lt;\/a&gt;.&lt;\/li&gt;\t&lt;li&gt;Older platforms: 32-bit OS support completely is dropped, vSphere 7.0 and higher only is supported, Windows Server and Hyper-V 2016 and Higher only are supported, these are two highlights but there are several more linked above.\u00a0&lt;\/li&gt;&lt;\/ul&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Small things that can make a big difference: &lt;\/strong&gt;Updated 4-September 2025&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;I want to highlight a few things that I feel users should know ahead of time to avoid any unforeseen circumstances. Here is a running list:&lt;\/p&gt;&lt;ul&gt;&lt;li&gt;Via FAQ on Forums: \u201cFor Veeam Essential licenses,&lt;strong&gt; initially VSA deployments will be supported only in a VM on any hypervisor supported by Veeam&lt;\/strong&gt;. Deployments on physical servers will not be supported due to the high cost and complexity of support cases that involve troubleshooting hardware-specific issues on non-Enterprise grade hardware smaller customers tend to use, as well as the sheer size of our Essentials customer base. Since this is intended to be a temporary limitation to help alleviate support load spike, we're not enforcing it in the product itself but with our Customer Support policies only. In future, we plan to allow using any server hardware that achieves the \&quot;Veeam Ready \u2013 Appliance\&quot; certification also for Veeam Essentials.\u201d\u00a0&lt;\/li&gt;\t&lt;li&gt;Via FAQ on Forums: Veeam Cloud Connect is not implemented in the Early Release.&lt;\/li&gt;\t&lt;li&gt;The OVA deployment of the Veeam Software Appliance is offered for VMware environments, for other supported hypervisors, use the ISO deployment matching the system requirements:\u00a0&lt;a href=\&quot;https:\/\/helpcenter.veeam.com\/rn\/veeam_backup_13_release_notes.html#system-requirements-\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Veeam Backup &amp;amp; Replication 13 Release Notes&lt;\/a&gt;&lt;\/li&gt;\t&lt;li&gt;FYI the Veeam Ready - Appliance qualified systems are here:\u00a0&lt;a href=\&quot;https:\/\/www.veeam.com\/partners\/alliance-partner-technical-programs.html?programCategory=veeam-ready-appliance\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Veeam Alliance Partner Technical Programs&lt;\/a&gt;&lt;\/li&gt;\t&lt;li&gt;Reminder if you missed it that with Early Release, upgrades and migrations are not offered. This is covered in the FAQ on the Forums as well. The Early Release is intended for net-new deployments.&lt;\/li&gt;&lt;\/ul&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;What about the rest of Veeam Data Platform?\u00a0&lt;\/strong&gt;Updated 4-September 2025&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;Veeam Backup &amp;amp; Replication was issued first with the Early Release on 3-September 2025, we expect general availability of the full Veeam Data Platform release (version 13.0.1) in Q4 2025. This will deliver fully featured V13 of the installable software for Microsoft Windows as well as the remaining functionality postponed from the early release of Veeam Software Appliance.&lt;\/p&gt;&lt;p&gt;&lt;strong&gt;Veeam ONE v13&lt;\/strong&gt;\u00a0has been released, this is generally available as Veeam ONE v13, you can read the &lt;strong&gt;&lt;a href=\&quot;https:\/\/www.veeam.com\/veeam_one_13_whats_new_wn.pdf\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;release notes here&lt;\/a&gt;&lt;\/strong&gt;. Downloads can be done from the My Account of the portal for V13 of Veeam ONE.&lt;\/p&gt;&lt;p&gt;&lt;strong&gt;Veeam Service Provider Console v9&lt;\/strong&gt; has also been released, you can read the &lt;strong&gt;&lt;a href=\&quot;https:\/\/www.veeam.com\/veeam_console_9_0_whats_new_wn.pdf\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;release notes here.&lt;\/a&gt;\u00a0&lt;\/strong&gt;Downloads can be done from the My Account of the portal for V9 of Veeam Service Provider Console.&lt;\/p&gt;&lt;p&gt;&lt;strong&gt;Veeam Recovery Orchestrator\u00a0&lt;\/strong&gt;is planned for a release that by Q4 that will complete the v13 platform set of products.&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;What is a Net-New Deployment?&lt;\/strong&gt;&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;For the Early Release milestone, this is deploying the Veeam Software Appliance and configuring it end-to-end in an environment to run Veeam Backup Enterprise Manager, Veeam Backup &amp;amp; Replication and optional extended roles like proxies, repositories and more.&lt;\/p&gt;&lt;p&gt;&lt;strong&gt;&lt;span style=\&quot;color:#c0392b;\&quot;&gt;Coming Soon: &lt;\/span&gt;Video Example of a Net New Deployment&lt;\/strong&gt;&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Stay Tuned for Updates&lt;\/strong&gt;&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;We have just launched our V13 journey, and we will keep this Upgrade Center current with information as the release progresses. Be sure to come back to check for more!&lt;\/p&gt;&quot;,&quot;id&quot;:10321,&quot;featuredImage&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/d6b8d3d6-1c8f-4547-9aa3-d5ad192cfd10_thumb.jpg&quot;,&quot;label&quot;:&quot;V13 Upgrade Center&quot;,&quot;replyCount&quot;:9,&quot;views&quot;:3847,&quot;post&quot;:{&quot;id&quot;:76953,&quot;author&quot;:{&quot;id&quot;:43,&quot;url&quot;:&quot;\/members\/rick-vanover-43&quot;,&quot;name&quot;:&quot;Rick Vanover&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/f17c2d16-8ff5-4a6f-ba3d-b1ee0cc1e0ef.png&quot;,&quot;userTitle&quot;:&quot;RICKATRON&quot;,&quot;rank&quot;:{&quot;isBold&quot;:false,&quot;isItalic&quot;:false,&quot;isUnderline&quot;:false,&quot;name&quot;:&quot;Community Manager&quot;},&quot;userLevel&quot;:7,&quot;badges&quot;:[{&quot;title&quot;:&quot;One of The First&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Awesome Blogger&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a272e27-c4af-4f65-bf08-934ce464b961_thumb.png&quot;},{&quot;title&quot;:&quot;Social Media Star&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6b46ecc9-710d-445e-a38e-6513646a507f_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Freshman&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/8e3e7146-9946-413d-8023-bbf7f3a3f49c_thumb.png&quot;},{&quot;title&quot;:&quot;Prolific Presenter&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/07dfdf35-5b39-43a9-831f-5eeb1fd331c2_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam Employee&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/91ad3502-fda1-459a-8a9e-ac0cf1cce178_thumb.png&quot;},{&quot;title&quot;:&quot;VeeamON Presenter&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/28780bc1-8081-4767-bda3-0d4833053fbe_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Recap Hero&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/f29017b8-1a67-4d46-9a9d-50bb41c8bf35_thumb.png&quot;},{&quot;title&quot;:&quot;Sys Admin Hero&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/8d945422-ef90-4e30-b8e6-fe70de56ee30_thumb.png&quot;}],&quot;isBanned&quot;:false},&quot;content&quot;:&quot;&lt;p&gt;Welcome to the V13 Upgrade Center, which will guide you through the process of this launch. For\u00a0&lt;strong&gt;V13,\u00a0&lt;\/strong&gt;some new improved availability and accelerations are in play; so this release will be one customers and partners should pay close attention to. The most important thing right from the top that we will start with for this one is current status and last update:&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Current Status: &lt;\/strong&gt;Veeam Software Appliance in Early Release&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;section class=\&quot;callout callout-blue\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Last Updated:\u00a0\u00a0&lt;\/strong&gt;4-September 2025&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;Before we dive into specifics and advice, it is important to orientate ourselves on where we are with this release. I\u2019ve prepared this&lt;strong&gt; Frequently Asked Questions&lt;\/strong&gt; list to get this started:&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;p&gt;&lt;strong&gt;Early Release FAQ\u00a0&lt;\/strong&gt;This section will deprecate in Q4 2025 - Updated 4-September 2025&lt;\/p&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;ul&gt;&lt;li&gt;&lt;strong&gt;Can I migrate from Veeam Backup &amp;amp; Replication 12.3 to the Veeam Software Appliance?\u00a0&lt;\/strong&gt;Not yet, but this will be available in a subsequent release.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;I just want to upgrade Veeam Backup &amp;amp; Replication on Windows, can I do that?\u00a0&lt;\/strong&gt;Not yet, but this will be available in a subsequent release.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;What is an Early Release?&lt;\/strong&gt;\u00a0This is a release that is simply early. This is a few months ahead of a full-fledged V13 release.\u00a0&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;Is the Early Release supported?\u00a0&lt;\/strong&gt;Yes, for active support contracts.\u00a0&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;What is the Veeam Software Appliance?\u00a0&lt;\/strong&gt;This is the pre-built, pre-hardened and predictable environment to run Veeam. This early release includes Veeam Backup &amp;amp; Replication 13.0.0 and additional appliances can be scaled out to run roles like proxies, repositories, mount servers and more. You may see it referred to as VSA here, from the Veeam team or in the Forums.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;What is the Early Release status suited for?&lt;\/strong&gt;\u00a0The Early Release of the Veeam Software Appliance is suited ideally for net-new deployments (i.e. environments that do not upgrade). Other use cases include advanced users with labs that are production-level to get a good feel for the Veeam Software Appliance.\u00a0&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;Are storage plug-ins ready for the Veeam Software Appliance during this Early Release status?&lt;\/strong&gt; Some of them are, this should be a consideration before deploying during the Early Release stage for net-new deployments, especially if routine other deployments in your organization have planned on the storage integrations.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;What about the Configuration Backup, can I use that to move to the Veeam Software Appliance?&lt;\/strong&gt; This is not offered at this time, the Veeam Software Appliance in Early Release Status is intended for net-new deployments.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;Where do I download the Veeam Software Appliance?&lt;\/strong&gt; The early release status is downloaded from the&lt;a href=\&quot;https:\/\/www.veeam.com\/products\/data-platform-trial-download.html?tab=vsa-download\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;&lt;strong&gt; Veeam website here&lt;\/strong&gt;&lt;\/a&gt;\u00a0(or from My Account). Be sure to click the \u2018tab\u2019 for the right mode:\t&lt;figure&gt;&lt;img alt=\&quot;\&quot; src=\&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/adf78e81-5092-4f4b-9c79-6e13f86a9787.png\&quot; \/&gt;&lt;\/figure&gt;&lt;p&gt;\u00a0&lt;\/p&gt;\t&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;Where can I get more information on this release? &lt;\/strong&gt;This &lt;a href=\&quot;https:\/\/forums.veeam.com\/veeam-backup-replication-f2\/frequently-asked-questions-release-schedule-and-deployment-options-t99995.html\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;&lt;strong&gt;Forum post&lt;\/strong&gt; &lt;\/a&gt;does a great job of overviewing the current status, &lt;a href=\&quot;https:\/\/forums.veeam.com\/veeam-backup-replication-f2\/current-version-t9456.html\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;&lt;strong&gt;current build information&lt;\/strong&gt;&lt;\/a&gt;, the &lt;strong&gt;&lt;a href=\&quot;https:\/\/www.veeam.com\/kb4738\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;Release Information KB&lt;\/a&gt;&lt;\/strong&gt;, the\u00a0&lt;a href=\&quot;https:\/\/www.veeam.com\/veeam_backup_13_whats_new__wn.pdf\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;&lt;strong&gt;What\u2019s New Document&lt;\/strong&gt;&lt;\/a&gt;, the &lt;strong&gt;&lt;a href=\&quot;https:\/\/helpcenter.veeam.com\/rn\/veeam_backup_13_release_notes.html#system-requirements-\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Release Notes&lt;\/a&gt;&lt;\/strong&gt;\u00a0as well as the whole of the\u00a0&lt;strong&gt;&lt;a href=\&quot;https:\/\/helpcenter.veeam.com\/\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Veeam Help Center.&lt;\/a&gt;&lt;\/strong&gt;&lt;\/li&gt;&lt;\/ul&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;p&gt;&lt;strong&gt;Overall FAQ&lt;\/strong&gt;: This section will persist past the Early Release stage - Updated 4-September 2025&lt;\/p&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;ul&gt;&lt;li&gt;&lt;strong&gt;What is the difference between\u00a0&lt;span style=\&quot;color:#16a085;\&quot;&gt;&lt;em&gt;migrate\u00a0&lt;\/em&gt;&lt;\/span&gt;and\u00a0&lt;span style=\&quot;color:#16a085;\&quot;&gt;&lt;em&gt;upgrade&lt;\/em&gt;\u00a0&lt;\/span&gt;for V13 of Veeam Backup &amp;amp; Replication?\u00a0&lt;\/strong&gt;A\u00a0&lt;span style=\&quot;color:#16a085;\&quot;&gt;&lt;em&gt;migration\u00a0&lt;\/em&gt;&lt;\/span&gt;will be going from Veeam Backup &amp;amp; Replication on Windows to the Veeam Software Appliance (changed environment). An\u00a0&lt;span style=\&quot;color:#16a085;\&quot;&gt;&lt;em&gt;upgrade\u00a0&lt;\/em&gt;&lt;\/span&gt;would be going from Veeam Backup &amp;amp; Replication V12.3 on Windows to Veeam Backup &amp;amp; Replication V13 on Windows (same environment). The Early Release does not offer either of these (this will change). If you are interested in migration to the Veeam Software Appliance with\u00a0conversion assistance and expert guidance, sign up for the\u00a0&lt;a href=\&quot;https:\/\/go.veeam.com\/vsa-conversion\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;Transition to the Veeam Software Appliance&lt;\/a&gt;\u00a0page.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;For Veeam Software Appliance deployments, what is different?\u00a0&lt;\/strong&gt;Generally speaking, the code and capabilities across Veeam Backup &amp;amp; Replication version 13 whether provided from the Veeam Sofware Appliance or installed on Windows will have a consistent set of capabilities, but there are differences to note:&lt;\/li&gt;&lt;\/ul&gt;&lt;table&gt;&lt;tbody&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;&lt;span style=\&quot;color:#16a085;\&quot;&gt;Characteristic&lt;\/span&gt;&lt;\/strong&gt;&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;&lt;strong&gt;&lt;span style=\&quot;color:#16a085;\&quot;&gt;Veeam Backup &amp;amp; Replication V13 on the Veeam Software Appliance &lt;\/span&gt;&lt;\/strong&gt;(in early release status)&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;&lt;strong&gt;&lt;span style=\&quot;color:#16a085;\&quot;&gt;Veeam Backup &amp;amp; Replication V13\u00a0on Windows &lt;\/span&gt;&lt;\/strong&gt;(not yet available)&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;Deployment&lt;\/strong&gt;&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;OVA or ISO will build the Veeam Backup &amp;amp; Replication (or a plain Just Enough OS for other roles) system.&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;ISO would mount and install application on a Windows system with user choices, database configuration, file and folder paths, account setup and more.&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;New capabilities&lt;\/strong&gt;&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;Same as V13 on Windows, except the following:&lt;br \/&gt;\t\t\t-High Availability will only function on the Veeam Software Appliance.&lt;br \/&gt;\t\t\t-The appliance management interface will only function on the Veeam Software Appliance.&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;\t\t\t&lt;p&gt;All V13 capabilities &lt;em&gt;except &lt;\/em&gt;what is noted on the other side.&lt;\/p&gt;\t\t\t&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;Planned dates (targets)&lt;\/strong&gt;&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;Early released on 3-September 2025&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;General availability for Veeam Data Platform is planned for Q4 2025 as installable&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;&lt;span style=\&quot;color:#3498db;\&quot;&gt;IMPORTANT:&lt;\/span&gt;&lt;\/strong&gt;&lt;br \/&gt;\t\t\tLicensing Models used&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;Veeam Universal License, Rental License, NFR&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;Veeam Universal License, Rental License, NFR, Socket-Based License, Community Edition&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;\/tbody&gt;&lt;\/table&gt;&lt;p&gt;\u00a0&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Deprecated Capabilities and Discontinued Features: &lt;span style=\&quot;color:#3498db;\&quot;&gt;Now &lt;\/span&gt;is the time to prepare&lt;\/strong&gt;&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;One of the important things I want to highlight came earlier this year as a number of deprecated and discontinued features have been shared. This makes now a very good time to focus on the\u00a0&lt;em&gt;non-net-new\u00a0&lt;\/em&gt;deployments to ensure that any deprecated capabilities or discontinued features are mitigated. See this post from earlier in the year:&lt;br \/&gt;\u00a0&lt;\/p&gt;&lt;p&gt;&lt;oembed url=\&quot;https:\/\/community.veeam.com\/blogs-and-podcasts-57\/via-veeam-forums-v13-deprecated-and-discontinued-features-for-our-2025-release-9494\&quot;&gt;&lt;\/oembed&gt;&lt;\/p&gt;&lt;p&gt;Please read through the above, noting the two Forum links, but the top ones that I see that would be a good topic to address now are:&lt;\/p&gt;&lt;ul&gt;&lt;li&gt;VBR: Deprecated reversed incremental backup mode.&lt;\/li&gt;\t&lt;li&gt;VBR: Configurations with backup jobs having backup metadata still not upgraded to V12 format (upgrades when they are productized will be blocked if not) - see\u00a0&lt;a href=\&quot;https:\/\/forums.veeam.com\/veeam-backup-replication-f2\/best-way-to-update-legacy-vmware-backup-copy-jobs-to-the-new-v12-standard-t85038.html\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;[V12] Best way to update Legacy VMWare Backup Copy jobs to the new V12 standard?&lt;\/a&gt;\u00a0and\u00a0&lt;a href=\&quot;https:\/\/helpcenter.veeam.com\/docs\/backup\/powershell\/convert-vbrlegacycopybackup.html?ver=120\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Convert-VBRLegacyCopyBackup - Veeam Backup PowerShell Reference&lt;\/a&gt;.&lt;\/li&gt;\t&lt;li&gt;Older platforms: 32-bit OS support completely is dropped, vSphere 7.0 and higher only is supported, Windows Server and Hyper-V 2016 and Higher only are supported, these are two highlights but there are several more linked above.\u00a0&lt;\/li&gt;&lt;\/ul&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Small things that can make a big difference: &lt;\/strong&gt;Updated 4-September 2025&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;I want to highlight a few things that I feel users should know ahead of time to avoid any unforeseen circumstances. Here is a running list:&lt;\/p&gt;&lt;ul&gt;&lt;li&gt;Via FAQ on Forums: \u201cFor Veeam Essential licenses,&lt;strong&gt; initially VSA deployments will be supported only in a VM on any hypervisor supported by Veeam&lt;\/strong&gt;. Deployments on physical servers will not be supported due to the high cost and complexity of support cases that involve troubleshooting hardware-specific issues on non-Enterprise grade hardware smaller customers tend to use, as well as the sheer size of our Essentials customer base. Since this is intended to be a temporary limitation to help alleviate support load spike, we're not enforcing it in the product itself but with our Customer Support policies only. In future, we plan to allow using any server hardware that achieves the \&quot;Veeam Ready \u2013 Appliance\&quot; certification also for Veeam Essentials.\u201d\u00a0&lt;\/li&gt;\t&lt;li&gt;Via FAQ on Forums: Veeam Cloud Connect is not implemented in the Early Release.&lt;\/li&gt;\t&lt;li&gt;The OVA deployment of the Veeam Software Appliance is offered for VMware environments, for other supported hypervisors, use the ISO deployment matching the system requirements:\u00a0&lt;a href=\&quot;https:\/\/helpcenter.veeam.com\/rn\/veeam_backup_13_release_notes.html#system-requirements-\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Veeam Backup &amp;amp; Replication 13 Release Notes&lt;\/a&gt;&lt;\/li&gt;\t&lt;li&gt;FYI the Veeam Ready - Appliance qualified systems are here:\u00a0&lt;a href=\&quot;https:\/\/www.veeam.com\/partners\/alliance-partner-technical-programs.html?programCategory=veeam-ready-appliance\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Veeam Alliance Partner Technical Programs&lt;\/a&gt;&lt;\/li&gt;\t&lt;li&gt;Reminder if you missed it that with Early Release, upgrades and migrations are not offered. This is covered in the FAQ on the Forums as well. The Early Release is intended for net-new deployments.&lt;\/li&gt;&lt;\/ul&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;What about the rest of Veeam Data Platform?\u00a0&lt;\/strong&gt;Updated 4-September 2025&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;Veeam Backup &amp;amp; Replication was issued first with the Early Release on 3-September 2025, we expect general availability of the full Veeam Data Platform release (version 13.0.1) in Q4 2025. This will deliver fully featured V13 of the installable software for Microsoft Windows as well as the remaining functionality postponed from the early release of Veeam Software Appliance.&lt;\/p&gt;&lt;p&gt;&lt;strong&gt;Veeam ONE v13&lt;\/strong&gt;\u00a0has been released, this is generally available as Veeam ONE v13, you can read the &lt;strong&gt;&lt;a href=\&quot;https:\/\/www.veeam.com\/veeam_one_13_whats_new_wn.pdf\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;release notes here&lt;\/a&gt;&lt;\/strong&gt;. Downloads can be done from the My Account of the portal for V13 of Veeam ONE.&lt;\/p&gt;&lt;p&gt;&lt;strong&gt;Veeam Service Provider Console v9&lt;\/strong&gt; has also been released, you can read the &lt;strong&gt;&lt;a href=\&quot;https:\/\/www.veeam.com\/veeam_console_9_0_whats_new_wn.pdf\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;release notes here.&lt;\/a&gt;\u00a0&lt;\/strong&gt;Downloads can be done from the My Account of the portal for V9 of Veeam Service Provider Console.&lt;\/p&gt;&lt;p&gt;&lt;strong&gt;Veeam Recovery Orchestrator\u00a0&lt;\/strong&gt;is planned for a release that by Q4 that will complete the v13 platform set of products.&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;What is a Net-New Deployment?&lt;\/strong&gt;&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;For the Early Release milestone, this is deploying the Veeam Software Appliance and configuring it end-to-end in an environment to run Veeam Backup Enterprise Manager, Veeam Backup &amp;amp; Replication and optional extended roles like proxies, repositories and more.&lt;\/p&gt;&lt;p&gt;&lt;strong&gt;&lt;span style=\&quot;color:#c0392b;\&quot;&gt;Coming Soon: &lt;\/span&gt;Video Example of a Net New Deployment&lt;\/strong&gt;&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Stay Tuned for Updates&lt;\/strong&gt;&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;We have just launched our V13 journey, and we will keep this Upgrade Center current with information as the release progresses. Be sure to come back to check for more!&lt;\/p&gt;&quot;,&quot;url&quot;:&quot;\/blogs-and-podcasts-57\/veeam-data-platform-v13-upgrade-center-10321?postid=76953#post76953&quot;,&quot;creationDate&quot;:&quot;2025-04-18T20:55:26+0000&quot;,&quot;relativeCreationDate&quot;:&quot;5 months ago&quot;},&quot;contentType&quot;:&quot;article&quot;,&quot;type&quot;:0,&quot;likes&quot;:25,&quot;hasCurrentUserLiked&quot;:false,&quot;hasBestAnswer&quot;:false},&quot;config&quot;:{&quot;selectedTopic&quot;:{&quot;url&quot;:&quot;https:\/\/community.veeam.com\/blogs-and-podcasts-57\/veeam-data-platform-v13-upgrade-center-10321&quot;,&quot;title&quot;:&quot;Veeam Data Platform v13 Upgrade Center&quot;,&quot;description&quot;:&quot;&lt;p&gt;Welcome to the V13 Upgrade Center, which will guide you through the process of this launch. For\u00a0&lt;strong&gt;V13,\u00a0&lt;\/strong&gt;some new improved availability and accelerations are in play; so this release will be one customers and partners should pay close attention to. The most important thing right from the top that we will start with for this one is current status and last update:&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Current Status: &lt;\/strong&gt;Veeam Software Appliance in Early Release&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;section class=\&quot;callout callout-blue\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Last Updated:\u00a0\u00a0&lt;\/strong&gt;4-September 2025&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;Before we dive into specifics and advice, it is important to orientate ourselves on where we are with this release. I\u2019ve prepared this&lt;strong&gt; Frequently Asked Questions&lt;\/strong&gt; list to get this started:&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;p&gt;&lt;strong&gt;Early Release FAQ\u00a0&lt;\/strong&gt;This section will deprecate in Q4 2025 - Updated 4-September 2025&lt;\/p&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;ul&gt;&lt;li&gt;&lt;strong&gt;Can I migrate from Veeam Backup &amp;amp; Replication 12.3 to the Veeam Software Appliance?\u00a0&lt;\/strong&gt;Not yet, but this will be available in a subsequent release.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;I just want to upgrade Veeam Backup &amp;amp; Replication on Windows, can I do that?\u00a0&lt;\/strong&gt;Not yet, but this will be available in a subsequent release.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;What is an Early Release?&lt;\/strong&gt;\u00a0This is a release that is simply early. This is a few months ahead of a full-fledged V13 release.\u00a0&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;Is the Early Release supported?\u00a0&lt;\/strong&gt;Yes, for active support contracts.\u00a0&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;What is the Veeam Software Appliance?\u00a0&lt;\/strong&gt;This is the pre-built, pre-hardened and predictable environment to run Veeam. This early release includes Veeam Backup &amp;amp; Replication 13.0.0 and additional appliances can be scaled out to run roles like proxies, repositories, mount servers and more. You may see it referred to as VSA here, from the Veeam team or in the Forums.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;What is the Early Release status suited for?&lt;\/strong&gt;\u00a0The Early Release of the Veeam Software Appliance is suited ideally for net-new deployments (i.e. environments that do not upgrade). Other use cases include advanced users with labs that are production-level to get a good feel for the Veeam Software Appliance.\u00a0&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;Are storage plug-ins ready for the Veeam Software Appliance during this Early Release status?&lt;\/strong&gt; Some of them are, this should be a consideration before deploying during the Early Release stage for net-new deployments, especially if routine other deployments in your organization have planned on the storage integrations.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;What about the Configuration Backup, can I use that to move to the Veeam Software Appliance?&lt;\/strong&gt; This is not offered at this time, the Veeam Software Appliance in Early Release Status is intended for net-new deployments.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;Where do I download the Veeam Software Appliance?&lt;\/strong&gt; The early release status is downloaded from the&lt;a href=\&quot;https:\/\/www.veeam.com\/products\/data-platform-trial-download.html?tab=vsa-download\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;&lt;strong&gt; Veeam website here&lt;\/strong&gt;&lt;\/a&gt;\u00a0(or from My Account). Be sure to click the \u2018tab\u2019 for the right mode:\t&lt;figure&gt;&lt;img alt=\&quot;\&quot; src=\&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/adf78e81-5092-4f4b-9c79-6e13f86a9787.png\&quot; \/&gt;&lt;\/figure&gt;&lt;p&gt;\u00a0&lt;\/p&gt;\t&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;Where can I get more information on this release? &lt;\/strong&gt;This &lt;a href=\&quot;https:\/\/forums.veeam.com\/veeam-backup-replication-f2\/frequently-asked-questions-release-schedule-and-deployment-options-t99995.html\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;&lt;strong&gt;Forum post&lt;\/strong&gt; &lt;\/a&gt;does a great job of overviewing the current status, &lt;a href=\&quot;https:\/\/forums.veeam.com\/veeam-backup-replication-f2\/current-version-t9456.html\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;&lt;strong&gt;current build information&lt;\/strong&gt;&lt;\/a&gt;, the &lt;strong&gt;&lt;a href=\&quot;https:\/\/www.veeam.com\/kb4738\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;Release Information KB&lt;\/a&gt;&lt;\/strong&gt;, the\u00a0&lt;a href=\&quot;https:\/\/www.veeam.com\/veeam_backup_13_whats_new__wn.pdf\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;&lt;strong&gt;What\u2019s New Document&lt;\/strong&gt;&lt;\/a&gt;, the &lt;strong&gt;&lt;a href=\&quot;https:\/\/helpcenter.veeam.com\/rn\/veeam_backup_13_release_notes.html#system-requirements-\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Release Notes&lt;\/a&gt;&lt;\/strong&gt;\u00a0as well as the whole of the\u00a0&lt;strong&gt;&lt;a href=\&quot;https:\/\/helpcenter.veeam.com\/\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Veeam Help Center.&lt;\/a&gt;&lt;\/strong&gt;&lt;\/li&gt;&lt;\/ul&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;p&gt;&lt;strong&gt;Overall FAQ&lt;\/strong&gt;: This section will persist past the Early Release stage - Updated 4-September 2025&lt;\/p&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;ul&gt;&lt;li&gt;&lt;strong&gt;What is the difference between\u00a0&lt;span style=\&quot;color:#16a085;\&quot;&gt;&lt;em&gt;migrate\u00a0&lt;\/em&gt;&lt;\/span&gt;and\u00a0&lt;span style=\&quot;color:#16a085;\&quot;&gt;&lt;em&gt;upgrade&lt;\/em&gt;\u00a0&lt;\/span&gt;for V13 of Veeam Backup &amp;amp; Replication?\u00a0&lt;\/strong&gt;A\u00a0&lt;span style=\&quot;color:#16a085;\&quot;&gt;&lt;em&gt;migration\u00a0&lt;\/em&gt;&lt;\/span&gt;will be going from Veeam Backup &amp;amp; Replication on Windows to the Veeam Software Appliance (changed environment). An\u00a0&lt;span style=\&quot;color:#16a085;\&quot;&gt;&lt;em&gt;upgrade\u00a0&lt;\/em&gt;&lt;\/span&gt;would be going from Veeam Backup &amp;amp; Replication V12.3 on Windows to Veeam Backup &amp;amp; Replication V13 on Windows (same environment). The Early Release does not offer either of these (this will change). If you are interested in migration to the Veeam Software Appliance with\u00a0conversion assistance and expert guidance, sign up for the\u00a0&lt;a href=\&quot;https:\/\/go.veeam.com\/vsa-conversion\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;Transition to the Veeam Software Appliance&lt;\/a&gt;\u00a0page.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;For Veeam Software Appliance deployments, what is different?\u00a0&lt;\/strong&gt;Generally speaking, the code and capabilities across Veeam Backup &amp;amp; Replication version 13 whether provided from the Veeam Sofware Appliance or installed on Windows will have a consistent set of capabilities, but there are differences to note:&lt;\/li&gt;&lt;\/ul&gt;&lt;table&gt;&lt;tbody&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;&lt;span style=\&quot;color:#16a085;\&quot;&gt;Characteristic&lt;\/span&gt;&lt;\/strong&gt;&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;&lt;strong&gt;&lt;span style=\&quot;color:#16a085;\&quot;&gt;Veeam Backup &amp;amp; Replication V13 on the Veeam Software Appliance &lt;\/span&gt;&lt;\/strong&gt;(in early release status)&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;&lt;strong&gt;&lt;span style=\&quot;color:#16a085;\&quot;&gt;Veeam Backup &amp;amp; Replication V13\u00a0on Windows &lt;\/span&gt;&lt;\/strong&gt;(not yet available)&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;Deployment&lt;\/strong&gt;&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;OVA or ISO will build the Veeam Backup &amp;amp; Replication (or a plain Just Enough OS for other roles) system.&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;ISO would mount and install application on a Windows system with user choices, database configuration, file and folder paths, account setup and more.&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;New capabilities&lt;\/strong&gt;&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;Same as V13 on Windows, except the following:&lt;br \/&gt;\t\t\t-High Availability will only function on the Veeam Software Appliance.&lt;br \/&gt;\t\t\t-The appliance management interface will only function on the Veeam Software Appliance.&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;\t\t\t&lt;p&gt;All V13 capabilities &lt;em&gt;except &lt;\/em&gt;what is noted on the other side.&lt;\/p&gt;\t\t\t&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;Planned dates (targets)&lt;\/strong&gt;&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;Early released on 3-September 2025&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;General availability for Veeam Data Platform is planned for Q4 2025 as installable&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;&lt;span style=\&quot;color:#3498db;\&quot;&gt;IMPORTANT:&lt;\/span&gt;&lt;\/strong&gt;&lt;br \/&gt;\t\t\tLicensing Models used&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;Veeam Universal License, Rental License, NFR&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;Veeam Universal License, Rental License, NFR, Socket-Based License, Community Edition&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;\/tbody&gt;&lt;\/table&gt;&lt;p&gt;\u00a0&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Deprecated Capabilities and Discontinued Features: &lt;span style=\&quot;color:#3498db;\&quot;&gt;Now &lt;\/span&gt;is the time to prepare&lt;\/strong&gt;&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;One of the important things I want to highlight came earlier this year as a number of deprecated and discontinued features have been shared. This makes now a very good time to focus on the\u00a0&lt;em&gt;non-net-new\u00a0&lt;\/em&gt;deployments to ensure that any deprecated capabilities or discontinued features are mitigated. See this post from earlier in the year:&lt;br \/&gt;\u00a0&lt;\/p&gt;&lt;p&gt;&lt;oembed url=\&quot;https:\/\/community.veeam.com\/blogs-and-podcasts-57\/via-veeam-forums-v13-deprecated-and-discontinued-features-for-our-2025-release-9494\&quot;&gt;&lt;\/oembed&gt;&lt;\/p&gt;&lt;p&gt;Please read through the above, noting the two Forum links, but the top ones that I see that would be a good topic to address now are:&lt;\/p&gt;&lt;ul&gt;&lt;li&gt;VBR: Deprecated reversed incremental backup mode.&lt;\/li&gt;\t&lt;li&gt;VBR: Configurations with backup jobs having backup metadata still not upgraded to V12 format (upgrades when they are productized will be blocked if not) - see\u00a0&lt;a href=\&quot;https:\/\/forums.veeam.com\/veeam-backup-replication-f2\/best-way-to-update-legacy-vmware-backup-copy-jobs-to-the-new-v12-standard-t85038.html\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;[V12] Best way to update Legacy VMWare Backup Copy jobs to the new V12 standard?&lt;\/a&gt;\u00a0and\u00a0&lt;a href=\&quot;https:\/\/helpcenter.veeam.com\/docs\/backup\/powershell\/convert-vbrlegacycopybackup.html?ver=120\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Convert-VBRLegacyCopyBackup - Veeam Backup PowerShell Reference&lt;\/a&gt;.&lt;\/li&gt;\t&lt;li&gt;Older platforms: 32-bit OS support completely is dropped, vSphere 7.0 and higher only is supported, Windows Server and Hyper-V 2016 and Higher only are supported, these are two highlights but there are several more linked above.\u00a0&lt;\/li&gt;&lt;\/ul&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Small things that can make a big difference: &lt;\/strong&gt;Updated 4-September 2025&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;I want to highlight a few things that I feel users should know ahead of time to avoid any unforeseen circumstances. Here is a running list:&lt;\/p&gt;&lt;ul&gt;&lt;li&gt;Via FAQ on Forums: \u201cFor Veeam Essential licenses,&lt;strong&gt; initially VSA deployments will be supported only in a VM on any hypervisor supported by Veeam&lt;\/strong&gt;. Deployments on physical servers will not be supported due to the high cost and complexity of support cases that involve troubleshooting hardware-specific issues on non-Enterprise grade hardware smaller customers tend to use, as well as the sheer size of our Essentials customer base. Since this is intended to be a temporary limitation to help alleviate support load spike, we're not enforcing it in the product itself but with our Customer Support policies only. In future, we plan to allow using any server hardware that achieves the \&quot;Veeam Ready \u2013 Appliance\&quot; certification also for Veeam Essentials.\u201d\u00a0&lt;\/li&gt;\t&lt;li&gt;Via FAQ on Forums: Veeam Cloud Connect is not implemented in the Early Release.&lt;\/li&gt;\t&lt;li&gt;The OVA deployment of the Veeam Software Appliance is offered for VMware environments, for other supported hypervisors, use the ISO deployment matching the system requirements:\u00a0&lt;a href=\&quot;https:\/\/helpcenter.veeam.com\/rn\/veeam_backup_13_release_notes.html#system-requirements-\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Veeam Backup &amp;amp; Replication 13 Release Notes&lt;\/a&gt;&lt;\/li&gt;\t&lt;li&gt;FYI the Veeam Ready - Appliance qualified systems are here:\u00a0&lt;a href=\&quot;https:\/\/www.veeam.com\/partners\/alliance-partner-technical-programs.html?programCategory=veeam-ready-appliance\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Veeam Alliance Partner Technical Programs&lt;\/a&gt;&lt;\/li&gt;\t&lt;li&gt;Reminder if you missed it that with Early Release, upgrades and migrations are not offered. This is covered in the FAQ on the Forums as well. The Early Release is intended for net-new deployments.&lt;\/li&gt;&lt;\/ul&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;What about the rest of Veeam Data Platform?\u00a0&lt;\/strong&gt;Updated 4-September 2025&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;Veeam Backup &amp;amp; Replication was issued first with the Early Release on 3-September 2025, we expect general availability of the full Veeam Data Platform release (version 13.0.1) in Q4 2025. This will deliver fully featured V13 of the installable software for Microsoft Windows as well as the remaining functionality postponed from the early release of Veeam Software Appliance.&lt;\/p&gt;&lt;p&gt;&lt;strong&gt;Veeam ONE v13&lt;\/strong&gt;\u00a0has been released, this is generally available as Veeam ONE v13, you can read the &lt;strong&gt;&lt;a href=\&quot;https:\/\/www.veeam.com\/veeam_one_13_whats_new_wn.pdf\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;release notes here&lt;\/a&gt;&lt;\/strong&gt;. Downloads can be done from the My Account of the portal for V13 of Veeam ONE.&lt;\/p&gt;&lt;p&gt;&lt;strong&gt;Veeam Service Provider Console v9&lt;\/strong&gt; has also been released, you can read the &lt;strong&gt;&lt;a href=\&quot;https:\/\/www.veeam.com\/veeam_console_9_0_whats_new_wn.pdf\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;release notes here.&lt;\/a&gt;\u00a0&lt;\/strong&gt;Downloads can be done from the My Account of the portal for V9 of Veeam Service Provider Console.&lt;\/p&gt;&lt;p&gt;&lt;strong&gt;Veeam Recovery Orchestrator\u00a0&lt;\/strong&gt;is planned for a release that by Q4 that will complete the v13 platform set of products.&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;What is a Net-New Deployment?&lt;\/strong&gt;&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;For the Early Release milestone, this is deploying the Veeam Software Appliance and configuring it end-to-end in an environment to run Veeam Backup Enterprise Manager, Veeam Backup &amp;amp; Replication and optional extended roles like proxies, repositories and more.&lt;\/p&gt;&lt;p&gt;&lt;strong&gt;&lt;span style=\&quot;color:#c0392b;\&quot;&gt;Coming Soon: &lt;\/span&gt;Video Example of a Net New Deployment&lt;\/strong&gt;&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Stay Tuned for Updates&lt;\/strong&gt;&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;We have just launched our V13 journey, and we will keep this Upgrade Center current with information as the release progresses. Be sure to come back to check for more!&lt;\/p&gt;&quot;,&quot;id&quot;:10321,&quot;featuredImage&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/d6b8d3d6-1c8f-4547-9aa3-d5ad192cfd10_thumb.jpg&quot;,&quot;label&quot;:&quot;V13 Upgrade Center&quot;,&quot;replyCount&quot;:9,&quot;views&quot;:3847,&quot;post&quot;:{&quot;id&quot;:76953,&quot;author&quot;:{&quot;id&quot;:43,&quot;url&quot;:&quot;\/members\/rick-vanover-43&quot;,&quot;name&quot;:&quot;Rick Vanover&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/f17c2d16-8ff5-4a6f-ba3d-b1ee0cc1e0ef.png&quot;,&quot;userTitle&quot;:&quot;RICKATRON&quot;,&quot;rank&quot;:{&quot;isBold&quot;:false,&quot;isItalic&quot;:false,&quot;isUnderline&quot;:false,&quot;name&quot;:&quot;Community Manager&quot;},&quot;userLevel&quot;:7,&quot;badges&quot;:[{&quot;title&quot;:&quot;One of The First&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Awesome Blogger&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a272e27-c4af-4f65-bf08-934ce464b961_thumb.png&quot;},{&quot;title&quot;:&quot;Social Media Star&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6b46ecc9-710d-445e-a38e-6513646a507f_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Freshman&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/8e3e7146-9946-413d-8023-bbf7f3a3f49c_thumb.png&quot;},{&quot;title&quot;:&quot;Prolific Presenter&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/07dfdf35-5b39-43a9-831f-5eeb1fd331c2_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam Employee&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/91ad3502-fda1-459a-8a9e-ac0cf1cce178_thumb.png&quot;},{&quot;title&quot;:&quot;VeeamON Presenter&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/28780bc1-8081-4767-bda3-0d4833053fbe_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Recap Hero&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/f29017b8-1a67-4d46-9a9d-50bb41c8bf35_thumb.png&quot;},{&quot;title&quot;:&quot;Sys Admin Hero&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/8d945422-ef90-4e30-b8e6-fe70de56ee30_thumb.png&quot;}],&quot;isBanned&quot;:false},&quot;content&quot;:&quot;&lt;p&gt;Welcome to the V13 Upgrade Center, which will guide you through the process of this launch. For\u00a0&lt;strong&gt;V13,\u00a0&lt;\/strong&gt;some new improved availability and accelerations are in play; so this release will be one customers and partners should pay close attention to. The most important thing right from the top that we will start with for this one is current status and last update:&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Current Status: &lt;\/strong&gt;Veeam Software Appliance in Early Release&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;section class=\&quot;callout callout-blue\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Last Updated:\u00a0\u00a0&lt;\/strong&gt;4-September 2025&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;Before we dive into specifics and advice, it is important to orientate ourselves on where we are with this release. I\u2019ve prepared this&lt;strong&gt; Frequently Asked Questions&lt;\/strong&gt; list to get this started:&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;p&gt;&lt;strong&gt;Early Release FAQ\u00a0&lt;\/strong&gt;This section will deprecate in Q4 2025 - Updated 4-September 2025&lt;\/p&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;ul&gt;&lt;li&gt;&lt;strong&gt;Can I migrate from Veeam Backup &amp;amp; Replication 12.3 to the Veeam Software Appliance?\u00a0&lt;\/strong&gt;Not yet, but this will be available in a subsequent release.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;I just want to upgrade Veeam Backup &amp;amp; Replication on Windows, can I do that?\u00a0&lt;\/strong&gt;Not yet, but this will be available in a subsequent release.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;What is an Early Release?&lt;\/strong&gt;\u00a0This is a release that is simply early. This is a few months ahead of a full-fledged V13 release.\u00a0&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;Is the Early Release supported?\u00a0&lt;\/strong&gt;Yes, for active support contracts.\u00a0&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;What is the Veeam Software Appliance?\u00a0&lt;\/strong&gt;This is the pre-built, pre-hardened and predictable environment to run Veeam. This early release includes Veeam Backup &amp;amp; Replication 13.0.0 and additional appliances can be scaled out to run roles like proxies, repositories, mount servers and more. You may see it referred to as VSA here, from the Veeam team or in the Forums.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;What is the Early Release status suited for?&lt;\/strong&gt;\u00a0The Early Release of the Veeam Software Appliance is suited ideally for net-new deployments (i.e. environments that do not upgrade). Other use cases include advanced users with labs that are production-level to get a good feel for the Veeam Software Appliance.\u00a0&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;Are storage plug-ins ready for the Veeam Software Appliance during this Early Release status?&lt;\/strong&gt; Some of them are, this should be a consideration before deploying during the Early Release stage for net-new deployments, especially if routine other deployments in your organization have planned on the storage integrations.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;What about the Configuration Backup, can I use that to move to the Veeam Software Appliance?&lt;\/strong&gt; This is not offered at this time, the Veeam Software Appliance in Early Release Status is intended for net-new deployments.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;Where do I download the Veeam Software Appliance?&lt;\/strong&gt; The early release status is downloaded from the&lt;a href=\&quot;https:\/\/www.veeam.com\/products\/data-platform-trial-download.html?tab=vsa-download\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;&lt;strong&gt; Veeam website here&lt;\/strong&gt;&lt;\/a&gt;\u00a0(or from My Account). Be sure to click the \u2018tab\u2019 for the right mode:\t&lt;figure&gt;&lt;img alt=\&quot;\&quot; src=\&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/adf78e81-5092-4f4b-9c79-6e13f86a9787.png\&quot; \/&gt;&lt;\/figure&gt;&lt;p&gt;\u00a0&lt;\/p&gt;\t&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;Where can I get more information on this release? &lt;\/strong&gt;This &lt;a href=\&quot;https:\/\/forums.veeam.com\/veeam-backup-replication-f2\/frequently-asked-questions-release-schedule-and-deployment-options-t99995.html\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;&lt;strong&gt;Forum post&lt;\/strong&gt; &lt;\/a&gt;does a great job of overviewing the current status, &lt;a href=\&quot;https:\/\/forums.veeam.com\/veeam-backup-replication-f2\/current-version-t9456.html\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;&lt;strong&gt;current build information&lt;\/strong&gt;&lt;\/a&gt;, the &lt;strong&gt;&lt;a href=\&quot;https:\/\/www.veeam.com\/kb4738\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;Release Information KB&lt;\/a&gt;&lt;\/strong&gt;, the\u00a0&lt;a href=\&quot;https:\/\/www.veeam.com\/veeam_backup_13_whats_new__wn.pdf\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;&lt;strong&gt;What\u2019s New Document&lt;\/strong&gt;&lt;\/a&gt;, the &lt;strong&gt;&lt;a href=\&quot;https:\/\/helpcenter.veeam.com\/rn\/veeam_backup_13_release_notes.html#system-requirements-\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Release Notes&lt;\/a&gt;&lt;\/strong&gt;\u00a0as well as the whole of the\u00a0&lt;strong&gt;&lt;a href=\&quot;https:\/\/helpcenter.veeam.com\/\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Veeam Help Center.&lt;\/a&gt;&lt;\/strong&gt;&lt;\/li&gt;&lt;\/ul&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;p&gt;&lt;strong&gt;Overall FAQ&lt;\/strong&gt;: This section will persist past the Early Release stage - Updated 4-September 2025&lt;\/p&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;ul&gt;&lt;li&gt;&lt;strong&gt;What is the difference between\u00a0&lt;span style=\&quot;color:#16a085;\&quot;&gt;&lt;em&gt;migrate\u00a0&lt;\/em&gt;&lt;\/span&gt;and\u00a0&lt;span style=\&quot;color:#16a085;\&quot;&gt;&lt;em&gt;upgrade&lt;\/em&gt;\u00a0&lt;\/span&gt;for V13 of Veeam Backup &amp;amp; Replication?\u00a0&lt;\/strong&gt;A\u00a0&lt;span style=\&quot;color:#16a085;\&quot;&gt;&lt;em&gt;migration\u00a0&lt;\/em&gt;&lt;\/span&gt;will be going from Veeam Backup &amp;amp; Replication on Windows to the Veeam Software Appliance (changed environment). An\u00a0&lt;span style=\&quot;color:#16a085;\&quot;&gt;&lt;em&gt;upgrade\u00a0&lt;\/em&gt;&lt;\/span&gt;would be going from Veeam Backup &amp;amp; Replication V12.3 on Windows to Veeam Backup &amp;amp; Replication V13 on Windows (same environment). The Early Release does not offer either of these (this will change). If you are interested in migration to the Veeam Software Appliance with\u00a0conversion assistance and expert guidance, sign up for the\u00a0&lt;a href=\&quot;https:\/\/go.veeam.com\/vsa-conversion\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;Transition to the Veeam Software Appliance&lt;\/a&gt;\u00a0page.&lt;\/li&gt;\t&lt;li&gt;&lt;strong&gt;For Veeam Software Appliance deployments, what is different?\u00a0&lt;\/strong&gt;Generally speaking, the code and capabilities across Veeam Backup &amp;amp; Replication version 13 whether provided from the Veeam Sofware Appliance or installed on Windows will have a consistent set of capabilities, but there are differences to note:&lt;\/li&gt;&lt;\/ul&gt;&lt;table&gt;&lt;tbody&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;&lt;span style=\&quot;color:#16a085;\&quot;&gt;Characteristic&lt;\/span&gt;&lt;\/strong&gt;&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;&lt;strong&gt;&lt;span style=\&quot;color:#16a085;\&quot;&gt;Veeam Backup &amp;amp; Replication V13 on the Veeam Software Appliance &lt;\/span&gt;&lt;\/strong&gt;(in early release status)&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;&lt;strong&gt;&lt;span style=\&quot;color:#16a085;\&quot;&gt;Veeam Backup &amp;amp; Replication V13\u00a0on Windows &lt;\/span&gt;&lt;\/strong&gt;(not yet available)&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;Deployment&lt;\/strong&gt;&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;OVA or ISO will build the Veeam Backup &amp;amp; Replication (or a plain Just Enough OS for other roles) system.&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;ISO would mount and install application on a Windows system with user choices, database configuration, file and folder paths, account setup and more.&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;New capabilities&lt;\/strong&gt;&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;Same as V13 on Windows, except the following:&lt;br \/&gt;\t\t\t-High Availability will only function on the Veeam Software Appliance.&lt;br \/&gt;\t\t\t-The appliance management interface will only function on the Veeam Software Appliance.&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;\t\t\t&lt;p&gt;All V13 capabilities &lt;em&gt;except &lt;\/em&gt;what is noted on the other side.&lt;\/p&gt;\t\t\t&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;Planned dates (targets)&lt;\/strong&gt;&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;Early released on 3-September 2025&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;General availability for Veeam Data Platform is planned for Q4 2025 as installable&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;tr&gt;&lt;td&gt;&lt;strong&gt;&lt;span style=\&quot;color:#3498db;\&quot;&gt;IMPORTANT:&lt;\/span&gt;&lt;\/strong&gt;&lt;br \/&gt;\t\t\tLicensing Models used&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:491px;\&quot;&gt;Veeam Universal License, Rental License, NFR&lt;\/td&gt;\t\t\t&lt;td style=\&quot;width:576px;\&quot;&gt;Veeam Universal License, Rental License, NFR, Socket-Based License, Community Edition&lt;\/td&gt;\t\t&lt;\/tr&gt;&lt;\/tbody&gt;&lt;\/table&gt;&lt;p&gt;\u00a0&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Deprecated Capabilities and Discontinued Features: &lt;span style=\&quot;color:#3498db;\&quot;&gt;Now &lt;\/span&gt;is the time to prepare&lt;\/strong&gt;&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;One of the important things I want to highlight came earlier this year as a number of deprecated and discontinued features have been shared. This makes now a very good time to focus on the\u00a0&lt;em&gt;non-net-new\u00a0&lt;\/em&gt;deployments to ensure that any deprecated capabilities or discontinued features are mitigated. See this post from earlier in the year:&lt;br \/&gt;\u00a0&lt;\/p&gt;&lt;p&gt;&lt;oembed url=\&quot;https:\/\/community.veeam.com\/blogs-and-podcasts-57\/via-veeam-forums-v13-deprecated-and-discontinued-features-for-our-2025-release-9494\&quot;&gt;&lt;\/oembed&gt;&lt;\/p&gt;&lt;p&gt;Please read through the above, noting the two Forum links, but the top ones that I see that would be a good topic to address now are:&lt;\/p&gt;&lt;ul&gt;&lt;li&gt;VBR: Deprecated reversed incremental backup mode.&lt;\/li&gt;\t&lt;li&gt;VBR: Configurations with backup jobs having backup metadata still not upgraded to V12 format (upgrades when they are productized will be blocked if not) - see\u00a0&lt;a href=\&quot;https:\/\/forums.veeam.com\/veeam-backup-replication-f2\/best-way-to-update-legacy-vmware-backup-copy-jobs-to-the-new-v12-standard-t85038.html\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;[V12] Best way to update Legacy VMWare Backup Copy jobs to the new V12 standard?&lt;\/a&gt;\u00a0and\u00a0&lt;a href=\&quot;https:\/\/helpcenter.veeam.com\/docs\/backup\/powershell\/convert-vbrlegacycopybackup.html?ver=120\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Convert-VBRLegacyCopyBackup - Veeam Backup PowerShell Reference&lt;\/a&gt;.&lt;\/li&gt;\t&lt;li&gt;Older platforms: 32-bit OS support completely is dropped, vSphere 7.0 and higher only is supported, Windows Server and Hyper-V 2016 and Higher only are supported, these are two highlights but there are several more linked above.\u00a0&lt;\/li&gt;&lt;\/ul&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Small things that can make a big difference: &lt;\/strong&gt;Updated 4-September 2025&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;I want to highlight a few things that I feel users should know ahead of time to avoid any unforeseen circumstances. Here is a running list:&lt;\/p&gt;&lt;ul&gt;&lt;li&gt;Via FAQ on Forums: \u201cFor Veeam Essential licenses,&lt;strong&gt; initially VSA deployments will be supported only in a VM on any hypervisor supported by Veeam&lt;\/strong&gt;. Deployments on physical servers will not be supported due to the high cost and complexity of support cases that involve troubleshooting hardware-specific issues on non-Enterprise grade hardware smaller customers tend to use, as well as the sheer size of our Essentials customer base. Since this is intended to be a temporary limitation to help alleviate support load spike, we're not enforcing it in the product itself but with our Customer Support policies only. In future, we plan to allow using any server hardware that achieves the \&quot;Veeam Ready \u2013 Appliance\&quot; certification also for Veeam Essentials.\u201d\u00a0&lt;\/li&gt;\t&lt;li&gt;Via FAQ on Forums: Veeam Cloud Connect is not implemented in the Early Release.&lt;\/li&gt;\t&lt;li&gt;The OVA deployment of the Veeam Software Appliance is offered for VMware environments, for other supported hypervisors, use the ISO deployment matching the system requirements:\u00a0&lt;a href=\&quot;https:\/\/helpcenter.veeam.com\/rn\/veeam_backup_13_release_notes.html#system-requirements-\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Veeam Backup &amp;amp; Replication 13 Release Notes&lt;\/a&gt;&lt;\/li&gt;\t&lt;li&gt;FYI the Veeam Ready - Appliance qualified systems are here:\u00a0&lt;a href=\&quot;https:\/\/www.veeam.com\/partners\/alliance-partner-technical-programs.html?programCategory=veeam-ready-appliance\&quot; rel=\&quot;noreferrer noopener\&quot; target=\&quot;_blank\&quot;&gt;Veeam Alliance Partner Technical Programs&lt;\/a&gt;&lt;\/li&gt;\t&lt;li&gt;Reminder if you missed it that with Early Release, upgrades and migrations are not offered. This is covered in the FAQ on the Forums as well. The Early Release is intended for net-new deployments.&lt;\/li&gt;&lt;\/ul&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;What about the rest of Veeam Data Platform?\u00a0&lt;\/strong&gt;Updated 4-September 2025&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;Veeam Backup &amp;amp; Replication was issued first with the Early Release on 3-September 2025, we expect general availability of the full Veeam Data Platform release (version 13.0.1) in Q4 2025. This will deliver fully featured V13 of the installable software for Microsoft Windows as well as the remaining functionality postponed from the early release of Veeam Software Appliance.&lt;\/p&gt;&lt;p&gt;&lt;strong&gt;Veeam ONE v13&lt;\/strong&gt;\u00a0has been released, this is generally available as Veeam ONE v13, you can read the &lt;strong&gt;&lt;a href=\&quot;https:\/\/www.veeam.com\/veeam_one_13_whats_new_wn.pdf\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;release notes here&lt;\/a&gt;&lt;\/strong&gt;. Downloads can be done from the My Account of the portal for V13 of Veeam ONE.&lt;\/p&gt;&lt;p&gt;&lt;strong&gt;Veeam Service Provider Console v9&lt;\/strong&gt; has also been released, you can read the &lt;strong&gt;&lt;a href=\&quot;https:\/\/www.veeam.com\/veeam_console_9_0_whats_new_wn.pdf\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;release notes here.&lt;\/a&gt;\u00a0&lt;\/strong&gt;Downloads can be done from the My Account of the portal for V9 of Veeam Service Provider Console.&lt;\/p&gt;&lt;p&gt;&lt;strong&gt;Veeam Recovery Orchestrator\u00a0&lt;\/strong&gt;is planned for a release that by Q4 that will complete the v13 platform set of products.&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;What is a Net-New Deployment?&lt;\/strong&gt;&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;For the Early Release milestone, this is deploying the Veeam Software Appliance and configuring it end-to-end in an environment to run Veeam Backup Enterprise Manager, Veeam Backup &amp;amp; Replication and optional extended roles like proxies, repositories and more.&lt;\/p&gt;&lt;p&gt;&lt;strong&gt;&lt;span style=\&quot;color:#c0392b;\&quot;&gt;Coming Soon: &lt;\/span&gt;Video Example of a Net New Deployment&lt;\/strong&gt;&lt;\/p&gt;&lt;section class=\&quot;callout callout-green\&quot;&gt;&lt;div&gt;&lt;h2&gt;&lt;strong&gt;Stay Tuned for Updates&lt;\/strong&gt;&lt;\/h2&gt;&lt;\/div&gt;&lt;\/section&gt;&lt;p&gt;We have just launched our V13 journey, and we will keep this Upgrade Center current with information as the release progresses. Be sure to come back to check for more!&lt;\/p&gt;&quot;,&quot;url&quot;:&quot;\/blogs-and-podcasts-57\/veeam-data-platform-v13-upgrade-center-10321?postid=76953#post76953&quot;,&quot;creationDate&quot;:&quot;2025-04-18T20:55:26+0000&quot;,&quot;relativeCreationDate&quot;:&quot;5 months ago&quot;},&quot;contentType&quot;:&quot;article&quot;,&quot;type&quot;:0,&quot;likes&quot;:25,&quot;hasCurrentUserLiked&quot;:false,&quot;hasBestAnswer&quot;:false}},&quot;phrases&quot;:{&quot;Forum&quot;:{&quot;{n} year|{n} years&quot;:&quot;{n} year|{n} years&quot;,&quot;{n} month|{n} months&quot;:&quot;{n} month|{n} months&quot;,&quot;{n} day|{n} days&quot;:&quot;{n} day|{n} days&quot;,&quot;{n} hour|{n} hours&quot;:&quot;{n} hour|{n} hours&quot;,&quot;{n} minute|{n} minutes&quot;:&quot;{n} minute|{n} minutes&quot;,&quot;just&quot;:&quot;just now&quot;,&quot;{plural} ago&quot;:&quot;{plural} ago&quot;}}}"><section role="group" class="topic_banner qa-topic_banner-container homepage-widget-wrapper homepage-widget-wrapper--no-spacing"><div class="sitewidth"><div class="col"><div class="topic-banner_wrapper featuredBanner"><a class="banner-notification_url" aria-labelledby="banner-data" href="https://community.veeam.com/blogs-and-podcasts-57/veeam-data-platform-v13-upgrade-center-10321"></a><div id="banner-data" class="box banner-notification notification"><div class="box__content box__pad"><p class="notification-title"><span class="notification-link">Veeam Data Platform v13 Upgrade Center</span></p><span class="thread-meta-item"><div class="avatar avatar avatar--S" style="float: none;"><div class="profilepicture qa-profile-picture"><a class="default-avatar-link qa-topic-meta-last-user-icon" href="/members/rick-vanover-43" rel="noreferrer"><img role="img" src="https://uploads-eu-west-1.insided.com/veeam-en/icon/200x200/f17c2d16-8ff5-4a6f-ba3d-b1ee0cc1e0ef.png" class="lazy" data-src="https://uploads-eu-west-1.insided.com/veeam-en/icon/200x200/f17c2d16-8ff5-4a6f-ba3d-b1ee0cc1e0ef.png" style="width: 100%;" title alt="Rick Vanover" /></a></div></div><span class="notification-link"><span class="thread-meta-item__date">5 months ago</span></span></span></div></div></div></div></div></section></div>
                                                            
                                    
                    <div data-preact="widget-breadcrumb/Breadcrumb" class="" data-props="{&quot;breadcrumbData&quot;:[{&quot;title&quot;:&quot;Community&quot;,&quot;url&quot;:&quot;\/&quot;},{&quot;title&quot;:&quot;Community&quot;,&quot;url&quot;:&quot;\/community-40&quot;},{&quot;title&quot;:&quot;YARA and Script Library&quot;,&quot;url&quot;:&quot;\/yara-and-script-library-67&quot;},{&quot;title&quot;:&quot;Featured YARA rule: Top 10 Ransomware Threats&quot;,&quot;url&quot;:&quot;\/yara-and-script-library-67\/featured-yara-rule-top-10-ransomware-threats-6267&quot;}]}"><div id="breadcrumbs-target" class="sitewidth breadcrumb-container"><div class="col main-navigation--breadcrumb-wrapper widget--breadcrumb"><ul class="breadcrumb"><li class="breadcrumb-item qa-breadcrumb-community"><a class="breadcrumb-item-link" href="/"><i class="icon icon--caret-left is-visible-S"></i>Community</a><i class="icon icon--caret-right"></i></li><li class="breadcrumb-item qa-breadcrumb-category"><a class="breadcrumb-item-link" href="/community-40"><i class="icon icon--caret-left is-visible-S"></i>Community</a><i class="icon icon--caret-right"></i></li><li class="breadcrumb-item qa-breadcrumb-forum"><a class="breadcrumb-item-link" href="/yara-and-script-library-67"><i class="icon icon--caret-left is-visible-S"></i>YARA and Script Library</a><i class="icon icon--caret-right"></i></li><li class="breadcrumb-item qa-breadcrumb-topic"><span class="current"><i class="icon icon--caret-left is-visible-S"></i>Featured YARA rule: Top 10 Ransomware Threats</span><i class="icon icon--caret-right"></i></li></ul></div></div></div>
        
        
                <script type="application/ld+json" nonce="">
        {"@context":"http:\/\/schema.org","@type":"NewsArticle","headline":"Featured YARA rule: Top 10 Ransomware Threats","datePublished":"2023-12-15T16:43:27+00:00","author":{"@type":"Person","name":"Rick Vanover","url":"\/members\/rick-vanover-43"},"image":[""]}
    </script>
    
        
<div class="full-width Template-header">
    <div class="sitewidth">
                            

            </div>
</div>
<div class="full-width Template-content">
    <div class="sitewidth">

    <div class="col col--main has--side qa-div-main" >
        <div class="box pagebox             box--unbox
        ">
            <div class="box__content">
                                                    
                            <div data-component="search-conversion"></div>
<div data-preact='destination/modules/Content/TopicView/index' data-props='{&quot;phrases&quot;:{&quot;Forum&quot;:{&quot;topic.closed.info_message&quot;:&quot;This topic has been closed for replies.&quot;,&quot;post.like.number.including_self&quot;:&quot;You and {numberOfLikes} other person like this|You and {numberOfLikes} other people like this&quot;,&quot;post.like.number.only_self&quot;:&quot;You like this&quot;,&quot;post.like.number&quot;:&quot;{numberOfLikes} person likes this|{numberOfLikes} people like this&quot;,&quot;tags.add&quot;:&quot;Add tags&quot;,&quot;validation.text.required&quot;:&quot;You have not entered any text yet.&quot;,&quot;topic_view.reported_content_modal.reason.placeholder&quot;:&quot;Type your reason here&quot;,&quot;topic_view.reported_content_modal.reason_not_provided.error&quot;:&quot;Please add your reason to the report.&quot;,&quot;Something&#039;s gone wrong.&quot;:&quot;Something&#039;s gone wrong.&quot;,&quot;pagination.label&quot;:&quot;Page&quot;,&quot;showFirstpost.message&quot;:&quot;Show first post&quot;,&quot;hideFirstpost.message&quot;:&quot;Hide first post&quot;,&quot;Best answer by&quot;:&quot;Best answer by&quot;,&quot;View original&quot;:&quot;View original&quot;,&quot;{n} year|{n} years&quot;:&quot;{n} year|{n} years&quot;,&quot;{n} month|{n} months&quot;:&quot;{n} month|{n} months&quot;,&quot;{n} day|{n} days&quot;:&quot;{n} day|{n} days&quot;,&quot;{n} hour|{n} hours&quot;:&quot;{n} hour|{n} hours&quot;,&quot;{n} minute|{n} minutes&quot;:&quot;{n} minute|{n} minutes&quot;,&quot;just&quot;:&quot;just now&quot;,&quot;{plural} ago&quot;:&quot;{plural} ago&quot;,&quot;sticky&quot;:&quot;Sticky&quot;,&quot;unmark.answer&quot;:&quot;Unmark answer&quot;,&quot;prefix.question&quot;:&quot;Question&quot;,&quot;prefix.answer&quot;:&quot;Solved&quot;,&quot;meta.views&quot;:&quot;2564 views&quot;,&quot;meta.replies&quot;:&quot;16 comments&quot;,&quot;meta.not_published&quot;:&quot;Not published&quot;,&quot;meta.last_edited&quot;:&quot;Last edited: {time}&quot;,&quot;product.areas.related.products&quot;:&quot;Related products&quot;,&quot;product.update.posted.in&quot;:&quot;Posted in&quot;,&quot;no.topics.found&quot;:&quot;No topics found&quot;,&quot;upvote&quot;:&quot;Upvote&quot;,&quot;translation.failure.show.original&quot;:&quot;View Original Content&quot;,&quot;translation.failure.retry&quot;:&quot;Retry Translation&quot;,&quot;translated.by.ai&quot;:&quot;Translated using AI&quot;,&quot;translating&quot;:&quot;Translating...&quot;,&quot;translate.all&quot;:&quot;Translate All&quot;,&quot;on.demand.translations.translate&quot;:&quot;Translate&quot;,&quot;on.demand.translation.failed&quot;:&quot;Sorry, something went wrong.&quot;,&quot;on.demand.translation.retry&quot;:&quot;Retry&quot;,&quot;hub_ai.on.demand.translations.show.original&quot;:&quot;Show original&quot;}},&quot;languageList&quot;:[],&quot;currentUser&quot;:{&quot;id&quot;:null,&quot;name&quot;:null,&quot;avatar&quot;:null,&quot;url&quot;:&quot;\/members\/-&quot;},&quot;authorData&quot;:{&quot;43&quot;:{&quot;id&quot;:43,&quot;url&quot;:&quot;\/members\/rick-vanover-43&quot;,&quot;name&quot;:&quot;Rick Vanover&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/f17c2d16-8ff5-4a6f-ba3d-b1ee0cc1e0ef.png&quot;,&quot;userTitle&quot;:&quot;RICKATRON&quot;,&quot;rank&quot;:{&quot;isBold&quot;:false,&quot;isItalic&quot;:false,&quot;isUnderline&quot;:false,&quot;name&quot;:&quot;Community Manager&quot;},&quot;userLevel&quot;:7,&quot;badges&quot;:[{&quot;title&quot;:&quot;One of The First&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Awesome Blogger&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a272e27-c4af-4f65-bf08-934ce464b961_thumb.png&quot;},{&quot;title&quot;:&quot;Social Media Star&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6b46ecc9-710d-445e-a38e-6513646a507f_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Freshman&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/8e3e7146-9946-413d-8023-bbf7f3a3f49c_thumb.png&quot;},{&quot;title&quot;:&quot;Prolific Presenter&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/07dfdf35-5b39-43a9-831f-5eeb1fd331c2_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam Employee&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/91ad3502-fda1-459a-8a9e-ac0cf1cce178_thumb.png&quot;},{&quot;title&quot;:&quot;VeeamON Presenter&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/28780bc1-8081-4767-bda3-0d4833053fbe_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Recap Hero&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/f29017b8-1a67-4d46-9a9d-50bb41c8bf35_thumb.png&quot;},{&quot;title&quot;:&quot;Sys Admin Hero&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/8d945422-ef90-4e30-b8e6-fe70de56ee30_thumb.png&quot;}],&quot;isBanned&quot;:false},&quot;49&quot;:{&quot;id&quot;:49,&quot;url&quot;:&quot;\/members\/chris-childerhose-49&quot;,&quot;name&quot;:&quot;Chris.Childerhose&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/d539317a-abac-4d80-84a9-ba24c43791d0.png&quot;,&quot;userTitle&quot;:&quot;Veeam Legend, Veeam Vanguard&quot;,&quot;rank&quot;:{&quot;isBold&quot;:false,&quot;isItalic&quot;:false,&quot;isUnderline&quot;:false,&quot;name&quot;:&quot;On the path to Greatness&quot;},&quot;userLevel&quot;:7,&quot;badges&quot;:[{&quot;title&quot;:&quot;VUG Leader&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/10869c83-c5bb-4598-bb7f-917d3c749a9e_thumb.png&quot;},{&quot;title&quot;:&quot;One of The First&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Pro&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/036252cd-25e2-4b2f-89cd-c059c32d0a68_thumb.png&quot;},{&quot;title&quot;:&quot;Awesome Blogger&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a272e27-c4af-4f65-bf08-934ce464b961_thumb.png&quot;},{&quot;title&quot;:&quot;Social Media Star&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6b46ecc9-710d-445e-a38e-6513646a507f_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Freshman&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/8e3e7146-9946-413d-8023-bbf7f3a3f49c_thumb.png&quot;},{&quot;title&quot;:&quot;Community Reviewer&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/39806849-2762-41ec-b920-4f6c85ce571f_thumb.png&quot;},{&quot;title&quot;:&quot;Conference Presenter&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/47212946-d245-4f50-848b-57de87a0a9c1_thumb.png&quot;},{&quot;title&quot;:&quot;Webinar Presenter&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/b45883a9-a2cf-4c58-a81c-79b51535e3dc_thumb.png&quot;},{&quot;title&quot;:&quot;VeeamON Presenter&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/28780bc1-8081-4767-bda3-0d4833053fbe_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Conversations Champion&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/469b9419-c544-442a-9f1a-8b73a40241f2_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Legend&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/770dded8-ce49-47ba-b217-332dd12347ec_thumb.png&quot;},{&quot;title&quot;:&quot;Recap Hero&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/f29017b8-1a67-4d46-9a9d-50bb41c8bf35_thumb.png&quot;},{&quot;title&quot;:&quot;VMCE Certified&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/5f763e37-ebb1-46c9-b18e-8f4fa7514006_thumb.png&quot;},{&quot;title&quot;:&quot;VMCA Certified&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/3ca0759a-1374-40f9-95b5-571b7f82da7a_thumb.png&quot;},{&quot;title&quot;:&quot;Community Superstar&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/bd8d36dc-74d6-4cdd-9fe8-2b6340cc10a8_thumb.png&quot;},{&quot;title&quot;:&quot;Vanguard&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/470fea88-5af6-446d-b0f9-8b0b49209cb1_thumb.png&quot;},{&quot;title&quot;:&quot;Community Einstein&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/b10081a5-44fc-40a8-9c23-a102ff74a358_thumb.png&quot;},{&quot;title&quot;:&quot;Community Hackathon Leader&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/7c60c947-83d3-4085-998f-2c0e8b4c918e_thumb.png&quot;},{&quot;title&quot;:&quot;Community Hackathon Winner&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/56972733-d614-4a5f-9e3f-675ceba4e74a_thumb.png&quot;}],&quot;isBanned&quot;:false},&quot;52&quot;:{&quot;id&quot;:52,&quot;url&quot;:&quot;\/members\/coolsport00-52&quot;,&quot;name&quot;:&quot;coolsport00&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/9e0d9630-afae-4442-830c-5ef5af2ba19a.png&quot;,&quot;userTitle&quot;:&quot;Veeam Legend&quot;,&quot;rank&quot;:{&quot;isBold&quot;:false,&quot;isItalic&quot;:false,&quot;isUnderline&quot;:false,&quot;name&quot;:&quot;On the path to Greatness&quot;},&quot;userLevel&quot;:7,&quot;badges&quot;:[{&quot;title&quot;:&quot;VUG Leader&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/10869c83-c5bb-4598-bb7f-917d3c749a9e_thumb.png&quot;},{&quot;title&quot;:&quot;One of The First&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Pro&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/036252cd-25e2-4b2f-89cd-c059c32d0a68_thumb.png&quot;},{&quot;title&quot;:&quot;Awesome Blogger&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a272e27-c4af-4f65-bf08-934ce464b961_thumb.png&quot;},{&quot;title&quot;:&quot;Social Media Star&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6b46ecc9-710d-445e-a38e-6513646a507f_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Freshman&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/8e3e7146-9946-413d-8023-bbf7f3a3f49c_thumb.png&quot;},{&quot;title&quot;:&quot;Community Reviewer&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/39806849-2762-41ec-b920-4f6c85ce571f_thumb.png&quot;},{&quot;title&quot;:&quot;VeeamON Presenter&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/28780bc1-8081-4767-bda3-0d4833053fbe_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Conversations Champion&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/469b9419-c544-442a-9f1a-8b73a40241f2_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Legend&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/770dded8-ce49-47ba-b217-332dd12347ec_thumb.png&quot;},{&quot;title&quot;:&quot;Recap Hero&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/f29017b8-1a67-4d46-9a9d-50bb41c8bf35_thumb.png&quot;},{&quot;title&quot;:&quot;VMCE Certified&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/5f763e37-ebb1-46c9-b18e-8f4fa7514006_thumb.png&quot;},{&quot;title&quot;:&quot;VMCA Certified&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/3ca0759a-1374-40f9-95b5-571b7f82da7a_thumb.png&quot;},{&quot;title&quot;:&quot;Community Superstar&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/bd8d36dc-74d6-4cdd-9fe8-2b6340cc10a8_thumb.png&quot;},{&quot;title&quot;:&quot;Vanguard&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/470fea88-5af6-446d-b0f9-8b0b49209cb1_thumb.png&quot;},{&quot;title&quot;:&quot;Cyber Protector&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/d238f283-1ae2-44b6-837f-0fdf50fa9ed8_thumb.png&quot;},{&quot;title&quot;:&quot;Community Einstein&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/b10081a5-44fc-40a8-9c23-a102ff74a358_thumb.png&quot;},{&quot;title&quot;:&quot;Blogger of the Month&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/4c3c991b-e513-4b02-a293-f69d9c26b118_thumb.png&quot;},{&quot;title&quot;:&quot;Community Hackathon Participant&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/a749d321-7c6c-4f7c-b06f-aee98b61028a_thumb.png&quot;},{&quot;title&quot;:&quot;V100 Show Presenter&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/8897d8e3-44ff-4e13-8499-24af9a94c8c3_thumb.png&quot;}],&quot;isBanned&quot;:false},&quot;227&quot;:{&quot;id&quot;:227,&quot;url&quot;:&quot;\/members\/bertrandfr-227&quot;,&quot;name&quot;:&quot;BertrandFR&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/c8fa2fb8-bbe2-4a9c-928e-68978454fb74.png&quot;,&quot;userTitle&quot;:&quot;Influencer&quot;,&quot;rank&quot;:{&quot;isBold&quot;:false,&quot;isItalic&quot;:false,&quot;isUnderline&quot;:false,&quot;name&quot;:&quot;Influencer&quot;},&quot;userLevel&quot;:7,&quot;badges&quot;:[{&quot;title&quot;:&quot;One of The First&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Webinar Presenter&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/b45883a9-a2cf-4c58-a81c-79b51535e3dc_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam Employee&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/91ad3502-fda1-459a-8a9e-ac0cf1cce178_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Conversations Champion&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/469b9419-c544-442a-9f1a-8b73a40241f2_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;VMCE Certified&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/5f763e37-ebb1-46c9-b18e-8f4fa7514006_thumb.png&quot;},{&quot;title&quot;:&quot;Former Legend&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/3ccb1b6d-f086-4851-9cb5-2d2af3dd4b2d_thumb.png&quot;}],&quot;isBanned&quot;:false},&quot;396&quot;:{&quot;id&quot;:396,&quot;url&quot;:&quot;\/members\/scott-396&quot;,&quot;name&quot;:&quot;Scott&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/bf4062d6-b3c3-49ea-810b-88e3cd73ab1e.png&quot;,&quot;userTitle&quot;:&quot;Veeam Legend&quot;,&quot;rank&quot;:{&quot;isBold&quot;:false,&quot;isItalic&quot;:false,&quot;isUnderline&quot;:false,&quot;name&quot;:&quot;On the path to Greatness&quot;},&quot;userLevel&quot;:7,&quot;badges&quot;:[{&quot;title&quot;:&quot;One of The First&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Pro&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/036252cd-25e2-4b2f-89cd-c059c32d0a68_thumb.png&quot;},{&quot;title&quot;:&quot;Awesome Blogger&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a272e27-c4af-4f65-bf08-934ce464b961_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Freshman&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/8e3e7146-9946-413d-8023-bbf7f3a3f49c_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Conversations Champion&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/469b9419-c544-442a-9f1a-8b73a40241f2_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Legend&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/770dded8-ce49-47ba-b217-332dd12347ec_thumb.png&quot;},{&quot;title&quot;:&quot;Blogger of the Month&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/4c3c991b-e513-4b02-a293-f69d9c26b118_thumb.png&quot;},{&quot;title&quot;:&quot;Sys Admin Hero&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/8d945422-ef90-4e30-b8e6-fe70de56ee30_thumb.png&quot;}],&quot;isBanned&quot;:false},&quot;418&quot;:{&quot;id&quot;:418,&quot;url&quot;:&quot;\/members\/jmousqueton-418&quot;,&quot;name&quot;:&quot;JMousqueton&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/38bad22f-3646-43cf-bc47-4dd54aafff97.png&quot;,&quot;userTitle&quot;:&quot;Veeam Vanguard&quot;,&quot;rank&quot;:{&quot;isBold&quot;:false,&quot;isItalic&quot;:false,&quot;isUnderline&quot;:false,&quot;name&quot;:&quot;Comes here often&quot;},&quot;userLevel&quot;:4,&quot;badges&quot;:[{&quot;title&quot;:&quot;VUG Leader&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/10869c83-c5bb-4598-bb7f-917d3c749a9e_thumb.png&quot;},{&quot;title&quot;:&quot;One of The First&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;VeeamON Presenter&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/28780bc1-8081-4767-bda3-0d4833053fbe_thumb.png&quot;},{&quot;title&quot;:&quot;Vanguard&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/470fea88-5af6-446d-b0f9-8b0b49209cb1_thumb.png&quot;}],&quot;isBanned&quot;:false},&quot;495&quot;:{&quot;id&quot;:495,&quot;url&quot;:&quot;\/members\/jmeixner-495&quot;,&quot;name&quot;:&quot;JMeixner&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/94bfbac0-fe92-4e81-9acc-49ae7deb127e.png&quot;,&quot;userTitle&quot;:&quot;On the path to Greatness&quot;,&quot;rank&quot;:{&quot;isBold&quot;:false,&quot;isItalic&quot;:false,&quot;isUnderline&quot;:false,&quot;name&quot;:&quot;On the path to Greatness&quot;},&quot;userLevel&quot;:7,&quot;badges&quot;:[{&quot;title&quot;:&quot;One of The First&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Pro&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/036252cd-25e2-4b2f-89cd-c059c32d0a68_thumb.png&quot;},{&quot;title&quot;:&quot;Awesome Blogger&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a272e27-c4af-4f65-bf08-934ce464b961_thumb.png&quot;},{&quot;title&quot;:&quot;Social Media Star&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6b46ecc9-710d-445e-a38e-6513646a507f_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Freshman&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/8e3e7146-9946-413d-8023-bbf7f3a3f49c_thumb.png&quot;},{&quot;title&quot;:&quot;Community Reviewer&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/39806849-2762-41ec-b920-4f6c85ce571f_thumb.png&quot;},{&quot;title&quot;:&quot;Webinar Presenter&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/b45883a9-a2cf-4c58-a81c-79b51535e3dc_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Conversations Champion&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/469b9419-c544-442a-9f1a-8b73a40241f2_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Recap Hero&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/f29017b8-1a67-4d46-9a9d-50bb41c8bf35_thumb.png&quot;},{&quot;title&quot;:&quot;VMCA Certified&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/3ca0759a-1374-40f9-95b5-571b7f82da7a_thumb.png&quot;},{&quot;title&quot;:&quot;Cyber Protector&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/d238f283-1ae2-44b6-837f-0fdf50fa9ed8_thumb.png&quot;},{&quot;title&quot;:&quot;Community Einstein&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/b10081a5-44fc-40a8-9c23-a102ff74a358_thumb.png&quot;},{&quot;title&quot;:&quot;Blogger of the Month&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/4c3c991b-e513-4b02-a293-f69d9c26b118_thumb.png&quot;},{&quot;title&quot;:&quot;Former Vanguard&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/72d7bd7a-9006-41a7-9a08-9c2c4e0cdb96_thumb.png&quot;},{&quot;title&quot;:&quot;Former Legend&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/3ccb1b6d-f086-4851-9cb5-2d2af3dd4b2d_thumb.png&quot;}],&quot;isBanned&quot;:false},&quot;588&quot;:{&quot;id&quot;:588,&quot;url&quot;:&quot;\/members\/link-state-588&quot;,&quot;name&quot;:&quot;Link State&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/0f3299a6-70d9-40e8-a3a8-ac5c3045a7c6.png&quot;,&quot;userTitle&quot;:&quot;Veeam Legend&quot;,&quot;rank&quot;:{&quot;isBold&quot;:false,&quot;isItalic&quot;:false,&quot;isUnderline&quot;:false,&quot;name&quot;:&quot;On the path to Greatness&quot;},&quot;userLevel&quot;:7,&quot;badges&quot;:[{&quot;title&quot;:&quot;One of The First&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Pro&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/036252cd-25e2-4b2f-89cd-c059c32d0a68_thumb.png&quot;},{&quot;title&quot;:&quot;Awesome Blogger&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a272e27-c4af-4f65-bf08-934ce464b961_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Freshman&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/8e3e7146-9946-413d-8023-bbf7f3a3f49c_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Conversations Champion&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/469b9419-c544-442a-9f1a-8b73a40241f2_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Legend&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/770dded8-ce49-47ba-b217-332dd12347ec_thumb.png&quot;},{&quot;title&quot;:&quot;Recap Hero&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/f29017b8-1a67-4d46-9a9d-50bb41c8bf35_thumb.png&quot;},{&quot;title&quot;:&quot;VMCE Certified&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/5f763e37-ebb1-46c9-b18e-8f4fa7514006_thumb.png&quot;},{&quot;title&quot;:&quot;VMCA Certified&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/3ca0759a-1374-40f9-95b5-571b7f82da7a_thumb.png&quot;},{&quot;title&quot;:&quot;Cyber Protector&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/d238f283-1ae2-44b6-837f-0fdf50fa9ed8_thumb.png&quot;}],&quot;isBanned&quot;:false},&quot;5028&quot;:{&quot;id&quot;:5028,&quot;url&quot;:&quot;\/members\/damien-commenge-5028&quot;,&quot;name&quot;:&quot;damien commenge&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/73470207-1e9b-41bb-b767-c5c821d5f181.png&quot;,&quot;userTitle&quot;:&quot;Veeam Legend&quot;,&quot;rank&quot;:{&quot;isBold&quot;:false,&quot;isItalic&quot;:false,&quot;isUnderline&quot;:false,&quot;name&quot;:&quot;Influencer&quot;},&quot;userLevel&quot;:7,&quot;badges&quot;:[{&quot;title&quot;:&quot;Proactive Veeam Forums User&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/da75b381-9a42-4f69-bbd0-85e22327b611_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Legend&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/770dded8-ce49-47ba-b217-332dd12347ec_thumb.png&quot;},{&quot;title&quot;:&quot;VMCE Certified&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/5f763e37-ebb1-46c9-b18e-8f4fa7514006_thumb.png&quot;},{&quot;title&quot;:&quot;VMCA Certified&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/3ca0759a-1374-40f9-95b5-571b7f82da7a_thumb.png&quot;}],&quot;isBanned&quot;:false},&quot;16379&quot;:{&quot;id&quot;:16379,&quot;url&quot;:&quot;\/members\/filik-16379&quot;,&quot;name&quot;:&quot;Filik&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/8148c11d-3024-4ecf-a3fa-388b922b2a4c.png&quot;,&quot;userTitle&quot;:&quot;New Here&quot;,&quot;rank&quot;:{&quot;isBold&quot;:false,&quot;isItalic&quot;:false,&quot;isUnderline&quot;:false,&quot;name&quot;:&quot;New Here&quot;},&quot;userLevel&quot;:0,&quot;badges&quot;:[],&quot;isBanned&quot;:false},&quot;17651&quot;:{&quot;id&quot;:17651,&quot;url&quot;:&quot;\/members\/waqasali-17651&quot;,&quot;name&quot;:&quot;waqasali&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/7ec0add9-b7f6-4643-a601-e46972df49a6.png&quot;,&quot;userTitle&quot;:&quot;Influencer&quot;,&quot;rank&quot;:{&quot;isBold&quot;:false,&quot;isItalic&quot;:false,&quot;isUnderline&quot;:false,&quot;name&quot;:&quot;Influencer&quot;},&quot;userLevel&quot;:7,&quot;badges&quot;:[{&quot;title&quot;:&quot;Veeam University Pro&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/036252cd-25e2-4b2f-89cd-c059c32d0a68_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Conversations Champion&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/469b9419-c544-442a-9f1a-8b73a40241f2_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;VMCE Certified&quot;,&quot;url&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/5f763e37-ebb1-46c9-b18e-8f4fa7514006_thumb.png&quot;}],&quot;isBanned&quot;:false},&quot;19413&quot;:{&quot;id&quot;:19413,&quot;url&quot;:&quot;\/members\/tim-dressel-19413&quot;,&quot;name&quot;:&quot;Tim Dressel&quot;,&quot;avatar&quot;:&quot;&quot;,&quot;userTitle&quot;:&quot;New Here&quot;,&quot;rank&quot;:{&quot;isBold&quot;:false,&quot;isItalic&quot;:false,&quot;isUnderline&quot;:false,&quot;name&quot;:&quot;New Here&quot;},&quot;userLevel&quot;:1,&quot;badges&quot;:[],&quot;isBanned&quot;:false},&quot;21163&quot;:{&quot;id&quot;:21163,&quot;url&quot;:&quot;\/members\/mmalarino-21163&quot;,&quot;name&quot;:&quot;mmalarino&quot;,&quot;avatar&quot;:&quot;&quot;,&quot;userTitle&quot;:&quot;New Here&quot;,&quot;rank&quot;:{&quot;isBold&quot;:false,&quot;isItalic&quot;:false,&quot;isUnderline&quot;:false,&quot;name&quot;:&quot;New Here&quot;},&quot;userLevel&quot;:0,&quot;badges&quot;:[],&quot;isBanned&quot;:false}},&quot;currentPage&quot;:1,&quot;topic&quot;:{&quot;id&quot;:264,&quot;threadId&quot;:6267,&quot;postId&quot;:51592,&quot;title&quot;:&quot;Featured YARA rule: Top 10 Ransomware Threats&quot;,&quot;contentType&quot;:&quot;article&quot;,&quot;content&quot;:&quot;&lt;p&gt;Now that V12.1 is available, I wanted to share with you a featured YARA rule set that can give you on-demand scanning for some top ransomware threats.\u00a0&lt;\/p&gt;&lt;p&gt;Attached to this post is a file named:\u00a0&lt;strong&gt;Top10RW_YARArules.zip.\u00a0&lt;\/strong&gt;In this file are YARA rules for some common ransomware threats that have been seen recently:&lt;\/p&gt;&lt;figure&gt;&lt;img alt=\&quot;\&quot; src=\&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/ce329148-f5a6-44c7-8783-38e12576b60f.png\&quot; \/&gt;&lt;\/figure&gt;&lt;p&gt;&lt;strong&gt;Attribution: &lt;\/strong&gt;This great collection was made by Felix Bilsten. Links: X:\u00a0&lt;a href=\&quot;https:\/\/twitter.com\/fxb_b\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;Felix Bilstein (@fxb_b) \/ X (twitter.com)&lt;\/a&gt;, website:\u00a0&lt;a href=\&quot;https:\/\/cocacoding.com\/\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;Felix Bilstein - project overview (cocacoding.com)&lt;\/a&gt;\u00a0and Github:\u00a0&lt;a href=\&quot;https:\/\/github.com\/fxb-cocacoding\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener\&quot;&gt;fxb-cocacoding (Felix Bilstein) \u00b7 GitHub&lt;\/a&gt;&lt;\/p&gt;&quot;,&quot;publishedAt&quot;:&quot;2023-12-15T16:43:27+00:00&quot;,&quot;author&quot;:{&quot;userId&quot;:43,&quot;username&quot;:&quot;Rick Vanover&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/f17c2d16-8ff5-4a6f-ba3d-b1ee0cc1e0ef.png&quot;,&quot;profileUrl&quot;:&quot;\/members\/rick-vanover-43&quot;,&quot;reputation&quot;:5974,&quot;rank&quot;:{&quot;id&quot;:&quot;1&quot;,&quot;name&quot;:&quot;Community Manager&quot;,&quot;avatarIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;usernameIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;styling&quot;:{&quot;bold&quot;:false,&quot;italic&quot;:false,&quot;underline&quot;:false,&quot;color&quot;:&quot;&quot;}},&quot;badges&quot;:[{&quot;title&quot;:&quot;One of The First&quot;,&quot;image&quot;:&quot;38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Awesome Blogger&quot;,&quot;image&quot;:&quot;6a272e27-c4af-4f65-bf08-934ce464b961_thumb.png&quot;},{&quot;title&quot;:&quot;Social Media Star&quot;,&quot;image&quot;:&quot;6b46ecc9-710d-445e-a38e-6513646a507f_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Freshman&quot;,&quot;image&quot;:&quot;8e3e7146-9946-413d-8023-bbf7f3a3f49c_thumb.png&quot;},{&quot;title&quot;:&quot;Prolific Presenter&quot;,&quot;image&quot;:&quot;07dfdf35-5b39-43a9-831f-5eeb1fd331c2_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam Employee&quot;,&quot;image&quot;:&quot;91ad3502-fda1-459a-8a9e-ac0cf1cce178_thumb.png&quot;},{&quot;title&quot;:&quot;VeeamON Presenter&quot;,&quot;image&quot;:&quot;28780bc1-8081-4767-bda3-0d4833053fbe_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;image&quot;:&quot;36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;image&quot;:&quot;6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Recap Hero&quot;,&quot;image&quot;:&quot;f29017b8-1a67-4d46-9a9d-50bb41c8bf35_thumb.png&quot;},{&quot;title&quot;:&quot;Sys Admin Hero&quot;,&quot;image&quot;:&quot;8d945422-ef90-4e30-b8e6-fe70de56ee30_thumb.png&quot;}],&quot;signature&quot;:&quot;Twitter @RickVanover | Email: rick.vanover@veeam.com&quot;,&quot;posts&quot;:820,&quot;customoptions&quot;:7,&quot;options&quot;:1024,&quot;usertitle&quot;:&quot;RICKATRON&quot;,&quot;customtitle&quot;:&quot;RICKATRON&quot;,&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;sticky&quot;:false,&quot;replyCount&quot;:16,&quot;likedBy&quot;:[&quot;588&quot;,&quot;49&quot;,&quot;12038&quot;,&quot;275&quot;,&quot;14624&quot;,&quot;227&quot;,&quot;6069&quot;,&quot;126&quot;,&quot;13013&quot;,&quot;17230&quot;,&quot;701&quot;,&quot;19796&quot;,&quot;613&quot;,&quot;10343&quot;,&quot;16379&quot;,&quot;17651&quot;,&quot;15704&quot;],&quot;poll&quot;:null,&quot;answeredPoll&quot;:false,&quot;tags&quot;:[&quot;Featured Yara Rule&quot;],&quot;forum&quot;:{&quot;url&quot;:&quot;\/yara-and-script-library-67&quot;,&quot;categoryId&quot;:67,&quot;title&quot;:&quot;YARA and Script Library&quot;,&quot;parent&quot;:{&quot;url&quot;:&quot;\/community-40&quot;,&quot;categoryId&quot;:40,&quot;title&quot;:&quot;Community&quot;,&quot;metaRobots&quot;:&quot;index, follow&quot;,&quot;type&quot;:0},&quot;metaRobots&quot;:&quot;index, follow&quot;,&quot;type&quot;:0},&quot;closed&quot;:false,&quot;lastEditedAt&quot;:&quot;2023-12-19T17:43:40+00:00&quot;,&quot;featuredImage&quot;:&quot;&quot;,&quot;featuredImageAltText&quot;:&quot;&quot;},&quot;pinnedReply&quot;:null,&quot;attachmentCdn&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/&quot;,&quot;disableFileAttachments&quot;:true,&quot;unlimitedEditPermission&quot;:false,&quot;contentHelpfulnessData&quot;:{&quot;topic&quot;:{&quot;id&quot;:6267,&quot;title&quot;:null,&quot;prefixId&quot;:null,&quot;contentType&quot;:&quot;article&quot;,&quot;views&quot;:2564},&quot;phrases&quot;:{&quot;Forum&quot;:{&quot;topic.helpfulness.text&quot;:&quot;Did this topic help you find an answer to your question?&quot;,&quot;topic.helpfulness.thanks&quot;:&quot;Thanks for your feedback&quot;,&quot;topic.helpfulness.indicator&quot;:&quot;found this helpful&quot;,&quot;topic_view.reported_content_modal.reason.placeholder&quot;:&quot;Type your reason here&quot;,&quot;topic_view.reported_content_modal.reason_not_provided.error&quot;:&quot;Please add your reason to the report.&quot;}}},&quot;topicContent&quot;:{&quot;showBadges&quot;:true,&quot;showReputation&quot;:true,&quot;showReport&quot;:false,&quot;canEndUserAddPublicTags&quot;:true,&quot;isPublicTagManagementEnabled&quot;:null,&quot;topicPrefixQuestion&quot;:&quot;vraag&quot;,&quot;topicPrefixAnswer&quot;:&quot;beantwoord&quot;,&quot;isPreview&quot;:null,&quot;featuredImage&quot;:null,&quot;publicLabel&quot;:&quot;&quot;,&quot;ideaStatus&quot;:null,&quot;productAreas&quot;:null,&quot;ssoLoginUrl&quot;:&quot;https:\/\/community.veeam.com\/ssoproxy\/login?ssoType=openidconnect&quot;},&quot;showPostActions&quot;:false,&quot;isTopicClosedForReply&quot;:false,&quot;shouldDisplayReplies&quot;:true,&quot;userHasPermissionToReply&quot;:false,&quot;repliesProps&quot;:{&quot;type&quot;:&quot;article&quot;,&quot;breadcrumbs&quot;:[{&quot;title&quot;:&quot;Community&quot;,&quot;url&quot;:&quot;\/&quot;},{&quot;title&quot;:&quot;Community&quot;,&quot;url&quot;:&quot;\/community-40&quot;},{&quot;title&quot;:&quot;YARA and Script Library&quot;,&quot;url&quot;:&quot;\/yara-and-script-library-67&quot;},{&quot;title&quot;:&quot;Featured YARA rule: Top 10 Ransomware Threats&quot;,&quot;url&quot;:&quot;\/yara-and-script-library-67\/featured-yara-rule-top-10-ransomware-threats-6267&quot;}],&quot;replies&quot;:[{&quot;postId&quot;:51595,&quot;privatePostId&quot;:3555,&quot;contentType&quot;:&quot;article_reply&quot;,&quot;author&quot;:{&quot;userId&quot;:49,&quot;username&quot;:&quot;Chris.Childerhose&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/d539317a-abac-4d80-84a9-ba24c43791d0.png&quot;,&quot;profileUrl&quot;:&quot;\/members\/chris-childerhose-49&quot;,&quot;reputation&quot;:20580,&quot;rank&quot;:{&quot;id&quot;:&quot;18&quot;,&quot;name&quot;:&quot;On the path to Greatness&quot;,&quot;avatarIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;usernameIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;styling&quot;:{&quot;bold&quot;:false,&quot;italic&quot;:false,&quot;underline&quot;:false,&quot;color&quot;:&quot;&quot;}},&quot;badges&quot;:[{&quot;title&quot;:&quot;VUG Leader&quot;,&quot;image&quot;:&quot;10869c83-c5bb-4598-bb7f-917d3c749a9e_thumb.png&quot;},{&quot;title&quot;:&quot;One of The First&quot;,&quot;image&quot;:&quot;38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Pro&quot;,&quot;image&quot;:&quot;036252cd-25e2-4b2f-89cd-c059c32d0a68_thumb.png&quot;},{&quot;title&quot;:&quot;Awesome Blogger&quot;,&quot;image&quot;:&quot;6a272e27-c4af-4f65-bf08-934ce464b961_thumb.png&quot;},{&quot;title&quot;:&quot;Social Media Star&quot;,&quot;image&quot;:&quot;6b46ecc9-710d-445e-a38e-6513646a507f_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Freshman&quot;,&quot;image&quot;:&quot;8e3e7146-9946-413d-8023-bbf7f3a3f49c_thumb.png&quot;},{&quot;title&quot;:&quot;Community Reviewer&quot;,&quot;image&quot;:&quot;39806849-2762-41ec-b920-4f6c85ce571f_thumb.png&quot;},{&quot;title&quot;:&quot;Conference Presenter&quot;,&quot;image&quot;:&quot;47212946-d245-4f50-848b-57de87a0a9c1_thumb.png&quot;},{&quot;title&quot;:&quot;Webinar Presenter&quot;,&quot;image&quot;:&quot;b45883a9-a2cf-4c58-a81c-79b51535e3dc_thumb.png&quot;},{&quot;title&quot;:&quot;VeeamON Presenter&quot;,&quot;image&quot;:&quot;28780bc1-8081-4767-bda3-0d4833053fbe_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;image&quot;:&quot;36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Conversations Champion&quot;,&quot;image&quot;:&quot;469b9419-c544-442a-9f1a-8b73a40241f2_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;image&quot;:&quot;6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Legend&quot;,&quot;image&quot;:&quot;770dded8-ce49-47ba-b217-332dd12347ec_thumb.png&quot;},{&quot;title&quot;:&quot;Recap Hero&quot;,&quot;image&quot;:&quot;f29017b8-1a67-4d46-9a9d-50bb41c8bf35_thumb.png&quot;},{&quot;title&quot;:&quot;VMCE Certified&quot;,&quot;image&quot;:&quot;5f763e37-ebb1-46c9-b18e-8f4fa7514006_thumb.png&quot;},{&quot;title&quot;:&quot;VMCA Certified&quot;,&quot;image&quot;:&quot;3ca0759a-1374-40f9-95b5-571b7f82da7a_thumb.png&quot;},{&quot;title&quot;:&quot;Community Superstar&quot;,&quot;image&quot;:&quot;bd8d36dc-74d6-4cdd-9fe8-2b6340cc10a8_thumb.png&quot;},{&quot;title&quot;:&quot;Vanguard&quot;,&quot;image&quot;:&quot;470fea88-5af6-446d-b0f9-8b0b49209cb1_thumb.png&quot;},{&quot;title&quot;:&quot;Community Einstein&quot;,&quot;image&quot;:&quot;b10081a5-44fc-40a8-9c23-a102ff74a358_thumb.png&quot;},{&quot;title&quot;:&quot;Community Hackathon Leader&quot;,&quot;image&quot;:&quot;7c60c947-83d3-4085-998f-2c0e8b4c918e_thumb.png&quot;},{&quot;title&quot;:&quot;Community Hackathon Winner&quot;,&quot;image&quot;:&quot;56972733-d614-4a5f-9e3f-675ceba4e74a_thumb.png&quot;}],&quot;signature&quot;:&quot;Chris Childerhose - VMCA2024 | VMCE2023 | VMCE-SP2024 | Veeam Vanguard 8* | Veeam Legend 5* | VUG Canada Leader | vExpert 6* | Toronto VMUG Leader | VCAP-DCV\/VCP-DCV | Object First Ace | Cisco Champion | Twitter: @cchilderhose | Blog Site \u2013 https:\/\/just-virtualization.tech&quot;,&quot;posts&quot;:9364,&quot;customoptions&quot;:7,&quot;options&quot;:1024,&quot;usertitle&quot;:&quot;Veeam Legend, Veeam Vanguard&quot;,&quot;customtitle&quot;:&quot;Veeam Legend, Veeam Vanguard&quot;,&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;content&quot;:&quot;&lt;p&gt;Thanks for sharing these, Rick.\u00a0 Looking forward to exploring Yara with 12.1.&lt;\/p&gt;&quot;,&quot;likes&quot;:[&quot;588&quot;,&quot;17230&quot;,&quot;17651&quot;],&quot;attachments&quot;:[],&quot;visible&quot;:true,&quot;ipAddress&quot;:&quot;&quot;,&quot;creationDate&quot;:&quot;2023-12-15T17:21:33+0000&quot;,&quot;isHighlighted&quot;:false,&quot;isPinned&quot;:false},{&quot;postId&quot;:51604,&quot;privatePostId&quot;:3557,&quot;contentType&quot;:&quot;article_reply&quot;,&quot;author&quot;:{&quot;userId&quot;:52,&quot;username&quot;:&quot;coolsport00&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/9e0d9630-afae-4442-830c-5ef5af2ba19a.png&quot;,&quot;profileUrl&quot;:&quot;\/members\/coolsport00-52&quot;,&quot;reputation&quot;:11676,&quot;rank&quot;:{&quot;id&quot;:&quot;18&quot;,&quot;name&quot;:&quot;On the path to Greatness&quot;,&quot;avatarIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;usernameIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;styling&quot;:{&quot;bold&quot;:false,&quot;italic&quot;:false,&quot;underline&quot;:false,&quot;color&quot;:&quot;&quot;}},&quot;badges&quot;:[{&quot;title&quot;:&quot;VUG Leader&quot;,&quot;image&quot;:&quot;10869c83-c5bb-4598-bb7f-917d3c749a9e_thumb.png&quot;},{&quot;title&quot;:&quot;One of The First&quot;,&quot;image&quot;:&quot;38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Pro&quot;,&quot;image&quot;:&quot;036252cd-25e2-4b2f-89cd-c059c32d0a68_thumb.png&quot;},{&quot;title&quot;:&quot;Awesome Blogger&quot;,&quot;image&quot;:&quot;6a272e27-c4af-4f65-bf08-934ce464b961_thumb.png&quot;},{&quot;title&quot;:&quot;Social Media Star&quot;,&quot;image&quot;:&quot;6b46ecc9-710d-445e-a38e-6513646a507f_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Freshman&quot;,&quot;image&quot;:&quot;8e3e7146-9946-413d-8023-bbf7f3a3f49c_thumb.png&quot;},{&quot;title&quot;:&quot;Community Reviewer&quot;,&quot;image&quot;:&quot;39806849-2762-41ec-b920-4f6c85ce571f_thumb.png&quot;},{&quot;title&quot;:&quot;VeeamON Presenter&quot;,&quot;image&quot;:&quot;28780bc1-8081-4767-bda3-0d4833053fbe_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;image&quot;:&quot;36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Conversations Champion&quot;,&quot;image&quot;:&quot;469b9419-c544-442a-9f1a-8b73a40241f2_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;image&quot;:&quot;6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Legend&quot;,&quot;image&quot;:&quot;770dded8-ce49-47ba-b217-332dd12347ec_thumb.png&quot;},{&quot;title&quot;:&quot;Recap Hero&quot;,&quot;image&quot;:&quot;f29017b8-1a67-4d46-9a9d-50bb41c8bf35_thumb.png&quot;},{&quot;title&quot;:&quot;VMCE Certified&quot;,&quot;image&quot;:&quot;5f763e37-ebb1-46c9-b18e-8f4fa7514006_thumb.png&quot;},{&quot;title&quot;:&quot;VMCA Certified&quot;,&quot;image&quot;:&quot;3ca0759a-1374-40f9-95b5-571b7f82da7a_thumb.png&quot;},{&quot;title&quot;:&quot;Community Superstar&quot;,&quot;image&quot;:&quot;bd8d36dc-74d6-4cdd-9fe8-2b6340cc10a8_thumb.png&quot;},{&quot;title&quot;:&quot;Vanguard&quot;,&quot;image&quot;:&quot;470fea88-5af6-446d-b0f9-8b0b49209cb1_thumb.png&quot;},{&quot;title&quot;:&quot;Cyber Protector&quot;,&quot;image&quot;:&quot;d238f283-1ae2-44b6-837f-0fdf50fa9ed8_thumb.png&quot;},{&quot;title&quot;:&quot;Community Einstein&quot;,&quot;image&quot;:&quot;b10081a5-44fc-40a8-9c23-a102ff74a358_thumb.png&quot;},{&quot;title&quot;:&quot;Blogger of the Month&quot;,&quot;image&quot;:&quot;4c3c991b-e513-4b02-a293-f69d9c26b118_thumb.png&quot;},{&quot;title&quot;:&quot;Community Hackathon Participant&quot;,&quot;image&quot;:&quot;a749d321-7c6c-4f7c-b06f-aee98b61028a_thumb.png&quot;},{&quot;title&quot;:&quot;V100 Show Presenter&quot;,&quot;image&quot;:&quot;8897d8e3-44ff-4e13-8499-24af9a94c8c3_thumb.png&quot;}],&quot;signature&quot;:&quot;Shane Williford - Veeam VMCA\/VMCE | Veeam Legend | VUG Leader | VCP-DCV | Twitter: @coolsport00&quot;,&quot;posts&quot;:4789,&quot;customoptions&quot;:15,&quot;options&quot;:1024,&quot;usertitle&quot;:&quot;Veeam Legend&quot;,&quot;customtitle&quot;:&quot;Veeam Legend&quot;,&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;content&quot;:&quot;&lt;p&gt;Fantastic Rick! Appreciate the share. Will look at this for sure after I get my environment upgraded.&lt;\/p&gt;&quot;,&quot;likes&quot;:[&quot;43&quot;,&quot;49&quot;,&quot;588&quot;,&quot;6069&quot;,&quot;17230&quot;,&quot;17651&quot;],&quot;attachments&quot;:[],&quot;visible&quot;:true,&quot;ipAddress&quot;:&quot;&quot;,&quot;creationDate&quot;:&quot;2023-12-15T18:49:11+0000&quot;,&quot;isHighlighted&quot;:false,&quot;isPinned&quot;:false},{&quot;postId&quot;:51605,&quot;privatePostId&quot;:3558,&quot;contentType&quot;:&quot;article_reply&quot;,&quot;author&quot;:{&quot;userId&quot;:43,&quot;username&quot;:&quot;Rick Vanover&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/f17c2d16-8ff5-4a6f-ba3d-b1ee0cc1e0ef.png&quot;,&quot;profileUrl&quot;:&quot;\/members\/rick-vanover-43&quot;,&quot;reputation&quot;:5974,&quot;rank&quot;:{&quot;id&quot;:&quot;1&quot;,&quot;name&quot;:&quot;Community Manager&quot;,&quot;avatarIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;usernameIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;styling&quot;:{&quot;bold&quot;:false,&quot;italic&quot;:false,&quot;underline&quot;:false,&quot;color&quot;:&quot;&quot;}},&quot;badges&quot;:[{&quot;title&quot;:&quot;One of The First&quot;,&quot;image&quot;:&quot;38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Awesome Blogger&quot;,&quot;image&quot;:&quot;6a272e27-c4af-4f65-bf08-934ce464b961_thumb.png&quot;},{&quot;title&quot;:&quot;Social Media Star&quot;,&quot;image&quot;:&quot;6b46ecc9-710d-445e-a38e-6513646a507f_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Freshman&quot;,&quot;image&quot;:&quot;8e3e7146-9946-413d-8023-bbf7f3a3f49c_thumb.png&quot;},{&quot;title&quot;:&quot;Prolific Presenter&quot;,&quot;image&quot;:&quot;07dfdf35-5b39-43a9-831f-5eeb1fd331c2_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam Employee&quot;,&quot;image&quot;:&quot;91ad3502-fda1-459a-8a9e-ac0cf1cce178_thumb.png&quot;},{&quot;title&quot;:&quot;VeeamON Presenter&quot;,&quot;image&quot;:&quot;28780bc1-8081-4767-bda3-0d4833053fbe_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;image&quot;:&quot;36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;image&quot;:&quot;6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Recap Hero&quot;,&quot;image&quot;:&quot;f29017b8-1a67-4d46-9a9d-50bb41c8bf35_thumb.png&quot;},{&quot;title&quot;:&quot;Sys Admin Hero&quot;,&quot;image&quot;:&quot;8d945422-ef90-4e30-b8e6-fe70de56ee30_thumb.png&quot;}],&quot;signature&quot;:&quot;Twitter @RickVanover | Email: rick.vanover@veeam.com&quot;,&quot;posts&quot;:820,&quot;customoptions&quot;:7,&quot;options&quot;:1024,&quot;usertitle&quot;:&quot;RICKATRON&quot;,&quot;customtitle&quot;:&quot;RICKATRON&quot;,&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;content&quot;:&quot;&lt;p&gt;Cheers, Shane.&lt;\/p&gt;&quot;,&quot;likes&quot;:[&quot;49&quot;,&quot;6069&quot;,&quot;17230&quot;,&quot;17651&quot;],&quot;attachments&quot;:[],&quot;visible&quot;:true,&quot;ipAddress&quot;:&quot;&quot;,&quot;creationDate&quot;:&quot;2023-12-15T18:51:39+0000&quot;,&quot;isHighlighted&quot;:false,&quot;isPinned&quot;:false},{&quot;postId&quot;:51620,&quot;privatePostId&quot;:3559,&quot;contentType&quot;:&quot;article_reply&quot;,&quot;author&quot;:{&quot;userId&quot;:495,&quot;username&quot;:&quot;JMeixner&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/94bfbac0-fe92-4e81-9acc-49ae7deb127e.png&quot;,&quot;profileUrl&quot;:&quot;\/members\/jmeixner-495&quot;,&quot;reputation&quot;:8747,&quot;rank&quot;:{&quot;id&quot;:&quot;18&quot;,&quot;name&quot;:&quot;On the path to Greatness&quot;,&quot;avatarIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;usernameIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;styling&quot;:{&quot;bold&quot;:false,&quot;italic&quot;:false,&quot;underline&quot;:false,&quot;color&quot;:&quot;&quot;}},&quot;badges&quot;:[{&quot;title&quot;:&quot;One of The First&quot;,&quot;image&quot;:&quot;38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Pro&quot;,&quot;image&quot;:&quot;036252cd-25e2-4b2f-89cd-c059c32d0a68_thumb.png&quot;},{&quot;title&quot;:&quot;Awesome Blogger&quot;,&quot;image&quot;:&quot;6a272e27-c4af-4f65-bf08-934ce464b961_thumb.png&quot;},{&quot;title&quot;:&quot;Social Media Star&quot;,&quot;image&quot;:&quot;6b46ecc9-710d-445e-a38e-6513646a507f_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Freshman&quot;,&quot;image&quot;:&quot;8e3e7146-9946-413d-8023-bbf7f3a3f49c_thumb.png&quot;},{&quot;title&quot;:&quot;Community Reviewer&quot;,&quot;image&quot;:&quot;39806849-2762-41ec-b920-4f6c85ce571f_thumb.png&quot;},{&quot;title&quot;:&quot;Webinar Presenter&quot;,&quot;image&quot;:&quot;b45883a9-a2cf-4c58-a81c-79b51535e3dc_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;image&quot;:&quot;36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Conversations Champion&quot;,&quot;image&quot;:&quot;469b9419-c544-442a-9f1a-8b73a40241f2_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;image&quot;:&quot;6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Recap Hero&quot;,&quot;image&quot;:&quot;f29017b8-1a67-4d46-9a9d-50bb41c8bf35_thumb.png&quot;},{&quot;title&quot;:&quot;VMCA Certified&quot;,&quot;image&quot;:&quot;3ca0759a-1374-40f9-95b5-571b7f82da7a_thumb.png&quot;},{&quot;title&quot;:&quot;Cyber Protector&quot;,&quot;image&quot;:&quot;d238f283-1ae2-44b6-837f-0fdf50fa9ed8_thumb.png&quot;},{&quot;title&quot;:&quot;Community Einstein&quot;,&quot;image&quot;:&quot;b10081a5-44fc-40a8-9c23-a102ff74a358_thumb.png&quot;},{&quot;title&quot;:&quot;Blogger of the Month&quot;,&quot;image&quot;:&quot;4c3c991b-e513-4b02-a293-f69d9c26b118_thumb.png&quot;},{&quot;title&quot;:&quot;Former Vanguard&quot;,&quot;image&quot;:&quot;72d7bd7a-9006-41a7-9a08-9c2c4e0cdb96_thumb.png&quot;},{&quot;title&quot;:&quot;Former Legend&quot;,&quot;image&quot;:&quot;3ccb1b6d-f086-4851-9cb5-2d2af3dd4b2d_thumb.png&quot;}],&quot;signature&quot;:&quot;Jochen (Joe) Meixner | Veeam Vanguard 2024 | Veeam Legend 2021 - 2024 | Veeam Certified Architect (VMCA) | X: @JoMeix | BlueSky: @jmeixner.bsky.social&quot;,&quot;posts&quot;:2686,&quot;customoptions&quot;:15,&quot;options&quot;:1024,&quot;usertitle&quot;:&quot;On the path to Greatness&quot;,&quot;customtitle&quot;:&quot;On the path to Greatness&quot;,&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;content&quot;:&quot;&lt;p&gt;Thanks Rick, I will try this on Monday \ud83d\ude0e\ud83d\udc4d\ud83c\udffc&lt;\/p&gt;&quot;,&quot;likes&quot;:[&quot;49&quot;,&quot;588&quot;,&quot;17230&quot;,&quot;17651&quot;],&quot;attachments&quot;:[],&quot;visible&quot;:true,&quot;ipAddress&quot;:&quot;&quot;,&quot;creationDate&quot;:&quot;2023-12-15T19:31:03+0000&quot;,&quot;isHighlighted&quot;:false,&quot;isPinned&quot;:false},{&quot;postId&quot;:51634,&quot;privatePostId&quot;:3562,&quot;contentType&quot;:&quot;article_reply&quot;,&quot;author&quot;:{&quot;userId&quot;:227,&quot;username&quot;:&quot;BertrandFR&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/c8fa2fb8-bbe2-4a9c-928e-68978454fb74.png&quot;,&quot;profileUrl&quot;:&quot;\/members\/bertrandfr-227&quot;,&quot;reputation&quot;:1535,&quot;rank&quot;:{&quot;id&quot;:&quot;19&quot;,&quot;name&quot;:&quot;Influencer&quot;,&quot;avatarIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;usernameIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;styling&quot;:{&quot;bold&quot;:false,&quot;italic&quot;:false,&quot;underline&quot;:false,&quot;color&quot;:&quot;&quot;}},&quot;badges&quot;:[{&quot;title&quot;:&quot;One of The First&quot;,&quot;image&quot;:&quot;38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Webinar Presenter&quot;,&quot;image&quot;:&quot;b45883a9-a2cf-4c58-a81c-79b51535e3dc_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam Employee&quot;,&quot;image&quot;:&quot;91ad3502-fda1-459a-8a9e-ac0cf1cce178_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;image&quot;:&quot;36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Conversations Champion&quot;,&quot;image&quot;:&quot;469b9419-c544-442a-9f1a-8b73a40241f2_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;image&quot;:&quot;6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;VMCE Certified&quot;,&quot;image&quot;:&quot;5f763e37-ebb1-46c9-b18e-8f4fa7514006_thumb.png&quot;},{&quot;title&quot;:&quot;Former Legend&quot;,&quot;image&quot;:&quot;3ccb1b6d-f086-4851-9cb5-2d2af3dd4b2d_thumb.png&quot;}],&quot;signature&quot;:&quot;&quot;,&quot;posts&quot;:528,&quot;customoptions&quot;:7,&quot;options&quot;:1024,&quot;usertitle&quot;:&quot;Influencer&quot;,&quot;customtitle&quot;:&quot;Influencer&quot;,&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;content&quot;:&quot;&lt;p&gt;Thanks for sharing &lt;user-mention data-id=\&quot;43\&quot;&gt;@Rick Vanover&lt;\/user-mention&gt;\u00a0, any comments about it\u00a0&lt;user-mention data-id=\&quot;215\&quot;&gt;@Julien Mousqueton&lt;\/user-mention&gt;\u00a0?&lt;\/p&gt;&quot;,&quot;likes&quot;:[&quot;49&quot;,&quot;588&quot;,&quot;17230&quot;,&quot;17651&quot;],&quot;attachments&quot;:[],&quot;visible&quot;:true,&quot;ipAddress&quot;:&quot;&quot;,&quot;creationDate&quot;:&quot;2023-12-16T12:00:32+0000&quot;,&quot;isHighlighted&quot;:false,&quot;isPinned&quot;:false},{&quot;postId&quot;:51718,&quot;privatePostId&quot;:3565,&quot;contentType&quot;:&quot;article_reply&quot;,&quot;author&quot;:{&quot;userId&quot;:396,&quot;username&quot;:&quot;Scott&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/bf4062d6-b3c3-49ea-810b-88e3cd73ab1e.png&quot;,&quot;profileUrl&quot;:&quot;\/members\/scott-396&quot;,&quot;reputation&quot;:3108,&quot;rank&quot;:{&quot;id&quot;:&quot;18&quot;,&quot;name&quot;:&quot;On the path to Greatness&quot;,&quot;avatarIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;usernameIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;styling&quot;:{&quot;bold&quot;:false,&quot;italic&quot;:false,&quot;underline&quot;:false,&quot;color&quot;:&quot;&quot;}},&quot;badges&quot;:[{&quot;title&quot;:&quot;One of The First&quot;,&quot;image&quot;:&quot;38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Pro&quot;,&quot;image&quot;:&quot;036252cd-25e2-4b2f-89cd-c059c32d0a68_thumb.png&quot;},{&quot;title&quot;:&quot;Awesome Blogger&quot;,&quot;image&quot;:&quot;6a272e27-c4af-4f65-bf08-934ce464b961_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Freshman&quot;,&quot;image&quot;:&quot;8e3e7146-9946-413d-8023-bbf7f3a3f49c_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;image&quot;:&quot;36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Conversations Champion&quot;,&quot;image&quot;:&quot;469b9419-c544-442a-9f1a-8b73a40241f2_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;image&quot;:&quot;6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Legend&quot;,&quot;image&quot;:&quot;770dded8-ce49-47ba-b217-332dd12347ec_thumb.png&quot;},{&quot;title&quot;:&quot;Blogger of the Month&quot;,&quot;image&quot;:&quot;4c3c991b-e513-4b02-a293-f69d9c26b118_thumb.png&quot;},{&quot;title&quot;:&quot;Sys Admin Hero&quot;,&quot;image&quot;:&quot;8d945422-ef90-4e30-b8e6-fe70de56ee30_thumb.png&quot;}],&quot;signature&quot;:&quot;&quot;,&quot;posts&quot;:1081,&quot;customoptions&quot;:7,&quot;options&quot;:1024,&quot;usertitle&quot;:&quot;Veeam Legend&quot;,&quot;customtitle&quot;:&quot;Veeam Legend&quot;,&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;content&quot;:&quot;&lt;p&gt;This is great. I\u2019ll add it to the lab this week!&lt;\/p&gt;&quot;,&quot;likes&quot;:[&quot;49&quot;,&quot;17230&quot;,&quot;17651&quot;],&quot;attachments&quot;:[],&quot;visible&quot;:true,&quot;ipAddress&quot;:&quot;&quot;,&quot;creationDate&quot;:&quot;2023-12-18T16:13:31+0000&quot;,&quot;isHighlighted&quot;:false,&quot;isPinned&quot;:false},{&quot;postId&quot;:51802,&quot;privatePostId&quot;:3567,&quot;contentType&quot;:&quot;article_reply&quot;,&quot;author&quot;:{&quot;userId&quot;:418,&quot;username&quot;:&quot;JMousqueton&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/38bad22f-3646-43cf-bc47-4dd54aafff97.png&quot;,&quot;profileUrl&quot;:&quot;\/members\/jmousqueton-418&quot;,&quot;reputation&quot;:64,&quot;rank&quot;:{&quot;id&quot;:&quot;13&quot;,&quot;name&quot;:&quot;Comes here often&quot;,&quot;avatarIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;usernameIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;styling&quot;:{&quot;bold&quot;:false,&quot;italic&quot;:false,&quot;underline&quot;:false,&quot;color&quot;:&quot;&quot;}},&quot;badges&quot;:[{&quot;title&quot;:&quot;VUG Leader&quot;,&quot;image&quot;:&quot;10869c83-c5bb-4598-bb7f-917d3c749a9e_thumb.png&quot;},{&quot;title&quot;:&quot;One of The First&quot;,&quot;image&quot;:&quot;38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;VeeamON Presenter&quot;,&quot;image&quot;:&quot;28780bc1-8081-4767-bda3-0d4833053fbe_thumb.png&quot;},{&quot;title&quot;:&quot;Vanguard&quot;,&quot;image&quot;:&quot;470fea88-5af6-446d-b0f9-8b0b49209cb1_thumb.png&quot;}],&quot;signature&quot;:&quot;&quot;,&quot;posts&quot;:10,&quot;customoptions&quot;:7,&quot;options&quot;:1024,&quot;usertitle&quot;:&quot;Veeam Vanguard&quot;,&quot;customtitle&quot;:&quot;Veeam Vanguard&quot;,&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;content&quot;:&quot;&lt;p&gt;&lt;user-mention data-id=\&quot;43\&quot;&gt;@Rick Vanover&lt;\/user-mention&gt;\u00a0&amp;amp; &lt;user-mention data-id=\&quot;227\&quot;&gt;@BertrandFR&lt;\/user-mention&gt;\u00a0&lt;\/p&gt;&lt;p&gt;Find bellow the golden mine of Yara rules :\u00a0&lt;\/p&gt;&lt;p&gt;&lt;a href=\&quot;https:\/\/yarahq.github.io\&quot; target=\&quot;_blank\&quot; rel=\&quot;noreferrer noopener nofollow ugc\&quot;&gt;https:\/\/yarahq.github.io&lt;\/a&gt;&lt;br \/&gt;\u00a0&lt;\/p&gt;&lt;p&gt;\u201cYARA Forge specializes in delivering high-quality YARA rule packages for immediate integration into security platforms. This tool automates the sourcing, standardization, and optimization of YARA rules from a variety of public repositories shared by different organizations and individuals. By collating these community-contributed rules, YARA Forge ensures that each package meets rigorous quality standards, offering a diverse and comprehensive rule set.\u201d\u00a0&lt;\/p&gt;&quot;,&quot;likes&quot;:[&quot;49&quot;,&quot;588&quot;,&quot;17230&quot;,&quot;19413&quot;,&quot;43&quot;,&quot;17651&quot;,&quot;17815&quot;],&quot;attachments&quot;:[],&quot;visible&quot;:true,&quot;ipAddress&quot;:&quot;&quot;,&quot;creationDate&quot;:&quot;2023-12-19T18:05:58+0000&quot;,&quot;isHighlighted&quot;:false,&quot;isPinned&quot;:false},{&quot;postId&quot;:51827,&quot;privatePostId&quot;:3568,&quot;contentType&quot;:&quot;article_reply&quot;,&quot;author&quot;:{&quot;userId&quot;:588,&quot;username&quot;:&quot;Link State&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/0f3299a6-70d9-40e8-a3a8-ac5c3045a7c6.png&quot;,&quot;profileUrl&quot;:&quot;\/members\/link-state-588&quot;,&quot;reputation&quot;:2223,&quot;rank&quot;:{&quot;id&quot;:&quot;18&quot;,&quot;name&quot;:&quot;On the path to Greatness&quot;,&quot;avatarIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;usernameIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;styling&quot;:{&quot;bold&quot;:false,&quot;italic&quot;:false,&quot;underline&quot;:false,&quot;color&quot;:&quot;&quot;}},&quot;badges&quot;:[{&quot;title&quot;:&quot;One of The First&quot;,&quot;image&quot;:&quot;38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Pro&quot;,&quot;image&quot;:&quot;036252cd-25e2-4b2f-89cd-c059c32d0a68_thumb.png&quot;},{&quot;title&quot;:&quot;Awesome Blogger&quot;,&quot;image&quot;:&quot;6a272e27-c4af-4f65-bf08-934ce464b961_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Freshman&quot;,&quot;image&quot;:&quot;8e3e7146-9946-413d-8023-bbf7f3a3f49c_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;image&quot;:&quot;36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Conversations Champion&quot;,&quot;image&quot;:&quot;469b9419-c544-442a-9f1a-8b73a40241f2_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;image&quot;:&quot;6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Legend&quot;,&quot;image&quot;:&quot;770dded8-ce49-47ba-b217-332dd12347ec_thumb.png&quot;},{&quot;title&quot;:&quot;Recap Hero&quot;,&quot;image&quot;:&quot;f29017b8-1a67-4d46-9a9d-50bb41c8bf35_thumb.png&quot;},{&quot;title&quot;:&quot;VMCE Certified&quot;,&quot;image&quot;:&quot;5f763e37-ebb1-46c9-b18e-8f4fa7514006_thumb.png&quot;},{&quot;title&quot;:&quot;VMCA Certified&quot;,&quot;image&quot;:&quot;3ca0759a-1374-40f9-95b5-571b7f82da7a_thumb.png&quot;},{&quot;title&quot;:&quot;Cyber Protector&quot;,&quot;image&quot;:&quot;d238f283-1ae2-44b6-837f-0fdf50fa9ed8_thumb.png&quot;}],&quot;signature&quot;:&quot;Veeam: VMCA | VMCE | VMXP | Veeam Legend  - Microsoft: MCITP | MCP | MCSA | 2008 R2 | 2012R2 | 2016 | MCSE Core Infrastructure | MCSE Cloud Platform - Azure: AZ900 | AZ104| AZ500 - AWS Cloud Practitioner - VMWare: VCP-DCV Vsphere 7.x - Cisco: CCNA (Expired)&quot;,&quot;posts&quot;:675,&quot;customoptions&quot;:15,&quot;options&quot;:1024,&quot;usertitle&quot;:&quot;Veeam Legend&quot;,&quot;customtitle&quot;:&quot;Veeam Legend&quot;,&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;content&quot;:&quot;&lt;p&gt;Thank you &lt;user-mention data-id=\&quot;43\&quot;&gt;@Rick Vanover&lt;\/user-mention&gt;\u00a0\u00a0everything seems okay.&lt;\/p&gt;&lt;p&gt;uploaded\u00a0C:\\Program Files\\Veeam\\Backup and Replication\\Backup\\YaraRules&lt;\/p&gt;&lt;p&gt;Launched scan yara medusa no error at the moment.&lt;br \/&gt;Thanks for sharing.&lt;\/p&gt;&lt;p&gt;\u00a0&lt;\/p&gt;&lt;figure&gt;&lt;img alt=\&quot;\&quot; src=\&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/attachment\/cb47ff34-9633-420a-bbde-add3ee46f10a.png\&quot; \/&gt;&lt;\/figure&gt;&lt;p&gt;\u00a0&lt;\/p&gt;&quot;,&quot;likes&quot;:[&quot;588&quot;,&quot;49&quot;,&quot;17230&quot;,&quot;613&quot;,&quot;17651&quot;],&quot;attachments&quot;:[],&quot;visible&quot;:true,&quot;ipAddress&quot;:&quot;&quot;,&quot;creationDate&quot;:&quot;2023-12-20T09:46:57+0000&quot;,&quot;isHighlighted&quot;:false,&quot;isPinned&quot;:false},{&quot;postId&quot;:51849,&quot;privatePostId&quot;:3569,&quot;contentType&quot;:&quot;article_reply&quot;,&quot;author&quot;:{&quot;userId&quot;:396,&quot;username&quot;:&quot;Scott&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/bf4062d6-b3c3-49ea-810b-88e3cd73ab1e.png&quot;,&quot;profileUrl&quot;:&quot;\/members\/scott-396&quot;,&quot;reputation&quot;:3108,&quot;rank&quot;:{&quot;id&quot;:&quot;18&quot;,&quot;name&quot;:&quot;On the path to Greatness&quot;,&quot;avatarIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;usernameIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;styling&quot;:{&quot;bold&quot;:false,&quot;italic&quot;:false,&quot;underline&quot;:false,&quot;color&quot;:&quot;&quot;}},&quot;badges&quot;:[{&quot;title&quot;:&quot;One of The First&quot;,&quot;image&quot;:&quot;38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Pro&quot;,&quot;image&quot;:&quot;036252cd-25e2-4b2f-89cd-c059c32d0a68_thumb.png&quot;},{&quot;title&quot;:&quot;Awesome Blogger&quot;,&quot;image&quot;:&quot;6a272e27-c4af-4f65-bf08-934ce464b961_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Freshman&quot;,&quot;image&quot;:&quot;8e3e7146-9946-413d-8023-bbf7f3a3f49c_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;image&quot;:&quot;36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Conversations Champion&quot;,&quot;image&quot;:&quot;469b9419-c544-442a-9f1a-8b73a40241f2_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;image&quot;:&quot;6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Legend&quot;,&quot;image&quot;:&quot;770dded8-ce49-47ba-b217-332dd12347ec_thumb.png&quot;},{&quot;title&quot;:&quot;Blogger of the Month&quot;,&quot;image&quot;:&quot;4c3c991b-e513-4b02-a293-f69d9c26b118_thumb.png&quot;},{&quot;title&quot;:&quot;Sys Admin Hero&quot;,&quot;image&quot;:&quot;8d945422-ef90-4e30-b8e6-fe70de56ee30_thumb.png&quot;}],&quot;signature&quot;:&quot;&quot;,&quot;posts&quot;:1081,&quot;customoptions&quot;:7,&quot;options&quot;:1024,&quot;usertitle&quot;:&quot;Veeam Legend&quot;,&quot;customtitle&quot;:&quot;Veeam Legend&quot;,&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;content&quot;:&quot;&lt;p&gt;Tested in my lab and it worked great. (minimal CPU available and a pretty small backup set)&lt;\/p&gt;&lt;p&gt;I\u2019m\u00a0excited to get more into Yara rules and look forward to posting some writeups and new rules for people to try on here.\u00a0&lt;\/p&gt;&quot;,&quot;likes&quot;:[&quot;49&quot;,&quot;588&quot;,&quot;17230&quot;,&quot;17651&quot;],&quot;attachments&quot;:[],&quot;visible&quot;:true,&quot;ipAddress&quot;:&quot;&quot;,&quot;creationDate&quot;:&quot;2023-12-20T16:41:41+0000&quot;,&quot;isHighlighted&quot;:false,&quot;isPinned&quot;:false},{&quot;postId&quot;:52515,&quot;privatePostId&quot;:3579,&quot;contentType&quot;:&quot;article_reply&quot;,&quot;author&quot;:{&quot;userId&quot;:19413,&quot;username&quot;:&quot;Tim Dressel&quot;,&quot;avatar&quot;:&quot;&quot;,&quot;profileUrl&quot;:&quot;\/members\/tim-dressel-19413&quot;,&quot;reputation&quot;:5,&quot;rank&quot;:{&quot;id&quot;:&quot;10&quot;,&quot;name&quot;:&quot;New Here&quot;,&quot;avatarIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;usernameIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;styling&quot;:{&quot;bold&quot;:false,&quot;italic&quot;:false,&quot;underline&quot;:false,&quot;color&quot;:&quot;&quot;}},&quot;badges&quot;:[],&quot;signature&quot;:&quot;&quot;,&quot;posts&quot;:2,&quot;customoptions&quot;:7,&quot;options&quot;:1024,&quot;usertitle&quot;:&quot;New Here&quot;,&quot;customtitle&quot;:&quot;New Here&quot;,&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;content&quot;:&quot;&lt;content-quote data-username=\&quot;JMousqueton\&quot;&gt;&lt;div class=\&quot;content-quote-content\&quot;&gt;\t&lt;p&gt;&lt;user-mention data-id=\&quot;43\&quot;&gt;@Rick Vanover&lt;\/user-mention&gt;\u00a0&amp;amp;\u00a0&lt;user-mention data-id=\&quot;227\&quot;&gt;@BertrandFR&lt;\/user-mention&gt;\u00a0&lt;\/p&gt;\t&lt;p&gt;Find bellow the golden mine of Yara rules :\u00a0&lt;\/p&gt;\t&lt;p&gt;&lt;a href=\&quot;https:\/\/yarahq.github.io\&quot; rel=\&quot;noreferrer noopener nofollow ugc\&quot; target=\&quot;_blank\&quot;&gt;https:\/\/yarahq.github.io&lt;\/a&gt;&lt;br \/&gt;\t\u00a0&lt;\/p&gt;\t&lt;p&gt;\u201cYARA Forge specializes in delivering high-quality YARA rule packages for immediate integration into security platforms. This tool automates the sourcing, standardization, and optimization of YARA rules from a variety of public repositories shared by different organizations and individuals. By collating these community-contributed rules, YARA Forge ensures that each package meets rigorous quality standards, offering a diverse and comprehensive rule set.\u201d\u00a0&lt;\/p&gt;\t&lt;\/div&gt;&lt;\/content-quote&gt;&lt;p&gt;Trying the core ruleset tonight!&lt;\/p&gt;&quot;,&quot;likes&quot;:[&quot;49&quot;,&quot;588&quot;,&quot;17230&quot;,&quot;17651&quot;],&quot;attachments&quot;:[],&quot;visible&quot;:true,&quot;ipAddress&quot;:&quot;&quot;,&quot;creationDate&quot;:&quot;2024-01-04T23:49:47+0000&quot;,&quot;isHighlighted&quot;:false,&quot;isPinned&quot;:false},{&quot;postId&quot;:52598,&quot;privatePostId&quot;:3580,&quot;contentType&quot;:&quot;article_reply&quot;,&quot;author&quot;:{&quot;userId&quot;:5028,&quot;username&quot;:&quot;damien commenge&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/73470207-1e9b-41bb-b767-c5c821d5f181.png&quot;,&quot;profileUrl&quot;:&quot;\/members\/damien-commenge-5028&quot;,&quot;reputation&quot;:370,&quot;rank&quot;:{&quot;id&quot;:&quot;19&quot;,&quot;name&quot;:&quot;Influencer&quot;,&quot;avatarIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;usernameIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;styling&quot;:{&quot;bold&quot;:false,&quot;italic&quot;:false,&quot;underline&quot;:false,&quot;color&quot;:&quot;&quot;}},&quot;badges&quot;:[{&quot;title&quot;:&quot;Proactive Veeam Forums User&quot;,&quot;image&quot;:&quot;da75b381-9a42-4f69-bbd0-85e22327b611_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;image&quot;:&quot;36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;image&quot;:&quot;6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Legend&quot;,&quot;image&quot;:&quot;770dded8-ce49-47ba-b217-332dd12347ec_thumb.png&quot;},{&quot;title&quot;:&quot;VMCE Certified&quot;,&quot;image&quot;:&quot;5f763e37-ebb1-46c9-b18e-8f4fa7514006_thumb.png&quot;},{&quot;title&quot;:&quot;VMCA Certified&quot;,&quot;image&quot;:&quot;3ca0759a-1374-40f9-95b5-571b7f82da7a_thumb.png&quot;}],&quot;signature&quot;:&quot;Keep learning day after day&quot;,&quot;posts&quot;:125,&quot;customoptions&quot;:7,&quot;options&quot;:1024,&quot;usertitle&quot;:&quot;Veeam Legend&quot;,&quot;customtitle&quot;:&quot;Veeam Legend&quot;,&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;content&quot;:&quot;&lt;p&gt;Hello,&lt;\/p&gt;&lt;p&gt;\u00a0&lt;\/p&gt;&lt;p&gt;Thanks for sharing it &lt;user-mention data-id=\&quot;43\&quot;&gt;@Rick Vanover&lt;\/user-mention&gt;\u00a0&lt;\/p&gt;&lt;p&gt;I\u2019m sorry but I \u2018m not sure to understand really what YARA rules are for ?\u00a0&lt;\/p&gt;&lt;p&gt;I need to select 1 rule like \u201ctest eicar\u201d for VBR to scan file backup and say me yes there is eicar on this file backup ?&lt;\/p&gt;&lt;p&gt;I\u2019m sorry I don\u2019t know anything about it but not sure I understand the benefits when I compare to other new 12.1 feature like inline detection (I don\u2019t have to create any rules) or suspicious activity detection ?&lt;br \/&gt;Thanks for your explanations :)&lt;\/p&gt;&quot;,&quot;likes&quot;:[&quot;588&quot;,&quot;17230&quot;,&quot;15593&quot;,&quot;17651&quot;],&quot;attachments&quot;:[],&quot;visible&quot;:true,&quot;ipAddress&quot;:&quot;&quot;,&quot;creationDate&quot;:&quot;2024-01-06T16:47:27+0000&quot;,&quot;isHighlighted&quot;:false,&quot;isPinned&quot;:false},{&quot;postId&quot;:61182,&quot;privatePostId&quot;:3908,&quot;contentType&quot;:&quot;article_reply&quot;,&quot;author&quot;:{&quot;userId&quot;:21163,&quot;username&quot;:&quot;mmalarino&quot;,&quot;avatar&quot;:&quot;&quot;,&quot;profileUrl&quot;:&quot;\/members\/mmalarino-21163&quot;,&quot;reputation&quot;:4,&quot;rank&quot;:{&quot;id&quot;:&quot;10&quot;,&quot;name&quot;:&quot;New Here&quot;,&quot;avatarIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;usernameIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;styling&quot;:{&quot;bold&quot;:false,&quot;italic&quot;:false,&quot;underline&quot;:false,&quot;color&quot;:&quot;&quot;}},&quot;badges&quot;:[],&quot;signature&quot;:&quot;&quot;,&quot;posts&quot;:2,&quot;customoptions&quot;:7,&quot;options&quot;:1024,&quot;usertitle&quot;:&quot;New Here&quot;,&quot;customtitle&quot;:&quot;New Here&quot;,&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;content&quot;:&quot;&lt;p&gt;The yara file adonunix alerts a lot of false positives, primarily it detects windows update packages as threats. Is this supposed to happen, or I should worry about it?&lt;\/p&gt;&lt;p&gt;\u00a0&lt;\/p&gt;&lt;p&gt;\u00a0&lt;\/p&gt;&quot;,&quot;likes&quot;:[&quot;17230&quot;,&quot;17651&quot;],&quot;attachments&quot;:[],&quot;visible&quot;:true,&quot;ipAddress&quot;:&quot;&quot;,&quot;creationDate&quot;:&quot;2024-05-20T19:43:32+0000&quot;,&quot;isHighlighted&quot;:false,&quot;isPinned&quot;:false},{&quot;postId&quot;:61185,&quot;privatePostId&quot;:3909,&quot;contentType&quot;:&quot;article_reply&quot;,&quot;author&quot;:{&quot;userId&quot;:43,&quot;username&quot;:&quot;Rick Vanover&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/f17c2d16-8ff5-4a6f-ba3d-b1ee0cc1e0ef.png&quot;,&quot;profileUrl&quot;:&quot;\/members\/rick-vanover-43&quot;,&quot;reputation&quot;:5974,&quot;rank&quot;:{&quot;id&quot;:&quot;1&quot;,&quot;name&quot;:&quot;Community Manager&quot;,&quot;avatarIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;usernameIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;styling&quot;:{&quot;bold&quot;:false,&quot;italic&quot;:false,&quot;underline&quot;:false,&quot;color&quot;:&quot;&quot;}},&quot;badges&quot;:[{&quot;title&quot;:&quot;One of The First&quot;,&quot;image&quot;:&quot;38cd469e-a981-470f-b2d1-aa4ee6e1aa61_thumb.png&quot;},{&quot;title&quot;:&quot;Awesome Blogger&quot;,&quot;image&quot;:&quot;6a272e27-c4af-4f65-bf08-934ce464b961_thumb.png&quot;},{&quot;title&quot;:&quot;Social Media Star&quot;,&quot;image&quot;:&quot;6b46ecc9-710d-445e-a38e-6513646a507f_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam University Freshman&quot;,&quot;image&quot;:&quot;8e3e7146-9946-413d-8023-bbf7f3a3f49c_thumb.png&quot;},{&quot;title&quot;:&quot;Prolific Presenter&quot;,&quot;image&quot;:&quot;07dfdf35-5b39-43a9-831f-5eeb1fd331c2_thumb.png&quot;},{&quot;title&quot;:&quot;Veeam Employee&quot;,&quot;image&quot;:&quot;91ad3502-fda1-459a-8a9e-ac0cf1cce178_thumb.png&quot;},{&quot;title&quot;:&quot;VeeamON Presenter&quot;,&quot;image&quot;:&quot;28780bc1-8081-4767-bda3-0d4833053fbe_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;image&quot;:&quot;36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;image&quot;:&quot;6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;Recap Hero&quot;,&quot;image&quot;:&quot;f29017b8-1a67-4d46-9a9d-50bb41c8bf35_thumb.png&quot;},{&quot;title&quot;:&quot;Sys Admin Hero&quot;,&quot;image&quot;:&quot;8d945422-ef90-4e30-b8e6-fe70de56ee30_thumb.png&quot;}],&quot;signature&quot;:&quot;Twitter @RickVanover | Email: rick.vanover@veeam.com&quot;,&quot;posts&quot;:820,&quot;customoptions&quot;:7,&quot;options&quot;:1024,&quot;usertitle&quot;:&quot;RICKATRON&quot;,&quot;customtitle&quot;:&quot;RICKATRON&quot;,&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;content&quot;:&quot;&lt;content-quote data-username=\&quot;mmalarino\&quot;&gt;&lt;div class=\&quot;content-quote-content\&quot;&gt;\t&lt;p&gt;The yara file adonunix alerts a lot of false positives, primarily it detects windows update packages as threats. Is this supposed to happen, or I should worry about it?&lt;\/p&gt;\t&lt;p&gt;\u00a0&lt;\/p&gt;\t&lt;p&gt;\u00a0&lt;\/p&gt;\t&lt;\/div&gt;&lt;\/content-quote&gt;&lt;p&gt;Hi &lt;user-mention data-id=\&quot;21163\&quot;&gt;@mmalarino&lt;\/user-mention&gt;\u00a0\u2192\u00a0Yes, windows update have also hit a lot of false positive for massive encryptions also. We are tuning the logic often. Stay tuned. And welcome to the Veeam community :)&lt;\/p&gt;&quot;,&quot;likes&quot;:[&quot;17230&quot;,&quot;396&quot;,&quot;17651&quot;],&quot;attachments&quot;:[],&quot;visible&quot;:true,&quot;ipAddress&quot;:&quot;&quot;,&quot;creationDate&quot;:&quot;2024-05-20T21:13:05+0000&quot;,&quot;isHighlighted&quot;:false,&quot;isPinned&quot;:false},{&quot;postId&quot;:61186,&quot;privatePostId&quot;:3910,&quot;contentType&quot;:&quot;article_reply&quot;,&quot;author&quot;:{&quot;userId&quot;:21163,&quot;username&quot;:&quot;mmalarino&quot;,&quot;avatar&quot;:&quot;&quot;,&quot;profileUrl&quot;:&quot;\/members\/mmalarino-21163&quot;,&quot;reputation&quot;:4,&quot;rank&quot;:{&quot;id&quot;:&quot;10&quot;,&quot;name&quot;:&quot;New Here&quot;,&quot;avatarIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;usernameIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;styling&quot;:{&quot;bold&quot;:false,&quot;italic&quot;:false,&quot;underline&quot;:false,&quot;color&quot;:&quot;&quot;}},&quot;badges&quot;:[],&quot;signature&quot;:&quot;&quot;,&quot;posts&quot;:2,&quot;customoptions&quot;:7,&quot;options&quot;:1024,&quot;usertitle&quot;:&quot;New Here&quot;,&quot;customtitle&quot;:&quot;New Here&quot;,&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;content&quot;:&quot;&lt;p&gt;&lt;user-mention data-id=\&quot;43\&quot;&gt;@Rick Vanover&lt;\/user-mention&gt;\u00a0thanks for the rules and the chance for a test. I&#039;ll be looking forward for more info!&lt;\/p&gt;&quot;,&quot;likes&quot;:[&quot;17230&quot;,&quot;17651&quot;],&quot;attachments&quot;:[],&quot;visible&quot;:true,&quot;ipAddress&quot;:&quot;&quot;,&quot;creationDate&quot;:&quot;2024-05-20T21:21:57+0000&quot;,&quot;isHighlighted&quot;:false,&quot;isPinned&quot;:false},{&quot;postId&quot;:81684,&quot;privatePostId&quot;:5210,&quot;contentType&quot;:&quot;article_reply&quot;,&quot;author&quot;:{&quot;userId&quot;:16379,&quot;username&quot;:&quot;Filik&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/8148c11d-3024-4ecf-a3fa-388b922b2a4c.png&quot;,&quot;profileUrl&quot;:&quot;\/members\/filik-16379&quot;,&quot;reputation&quot;:3,&quot;rank&quot;:{&quot;id&quot;:&quot;10&quot;,&quot;name&quot;:&quot;New Here&quot;,&quot;avatarIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;usernameIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;styling&quot;:{&quot;bold&quot;:false,&quot;italic&quot;:false,&quot;underline&quot;:false,&quot;color&quot;:&quot;&quot;}},&quot;badges&quot;:[],&quot;signature&quot;:&quot;4 Times VMCE - Veeam 4 Life&quot;,&quot;posts&quot;:2,&quot;customoptions&quot;:7,&quot;options&quot;:1024,&quot;usertitle&quot;:&quot;New Here&quot;,&quot;customtitle&quot;:&quot;New Here&quot;,&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;content&quot;:&quot;&lt;p&gt;Thanks Rick, I was looking for something like this.&lt;br \/&gt;&lt;br \/&gt;I went and merged all of the 10 rules from the zip in one single .yar file, so its one entry to select it and wait for the scan outcome.&lt;\/p&gt;&quot;,&quot;likes&quot;:[&quot;17651&quot;],&quot;attachments&quot;:[],&quot;visible&quot;:true,&quot;ipAddress&quot;:&quot;&quot;,&quot;creationDate&quot;:&quot;2025-08-14T13:51:42+0000&quot;,&quot;isHighlighted&quot;:false,&quot;isPinned&quot;:false},{&quot;postId&quot;:81773,&quot;privatePostId&quot;:5238,&quot;contentType&quot;:&quot;article_reply&quot;,&quot;author&quot;:{&quot;userId&quot;:17651,&quot;username&quot;:&quot;waqasali&quot;,&quot;avatar&quot;:&quot;https:\/\/uploads-eu-west-1.insided.com\/veeam-en\/icon\/200x200\/7ec0add9-b7f6-4643-a601-e46972df49a6.png&quot;,&quot;profileUrl&quot;:&quot;\/members\/waqasali-17651&quot;,&quot;reputation&quot;:447,&quot;rank&quot;:{&quot;id&quot;:&quot;19&quot;,&quot;name&quot;:&quot;Influencer&quot;,&quot;avatarIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;usernameIcon&quot;:{&quot;source&quot;:&quot;&quot;,&quot;thumbnail&quot;:&quot;&quot;},&quot;styling&quot;:{&quot;bold&quot;:false,&quot;italic&quot;:false,&quot;underline&quot;:false,&quot;color&quot;:&quot;&quot;}},&quot;badges&quot;:[{&quot;title&quot;:&quot;Veeam University Pro&quot;,&quot;image&quot;:&quot;036252cd-25e2-4b2f-89cd-c059c32d0a68_thumb.png&quot;},{&quot;title&quot;:&quot;Active VUG Member&quot;,&quot;image&quot;:&quot;36069c41-5db2-4470-9a0e-52b74a3e4772_thumb.png&quot;},{&quot;title&quot;:&quot;Conversations Champion&quot;,&quot;image&quot;:&quot;469b9419-c544-442a-9f1a-8b73a40241f2_thumb.png&quot;},{&quot;title&quot;:&quot;Discussions Guardian&quot;,&quot;image&quot;:&quot;6a23ddbb-d73b-44d8-86e7-1611b767f939_thumb.png&quot;},{&quot;title&quot;:&quot;VMCE Certified&quot;,&quot;image&quot;:&quot;5f763e37-ebb1-46c9-b18e-8f4fa7514006_thumb.png&quot;}],&quot;signature&quot;:&quot;Waqas Ali&quot;,&quot;posts&quot;:338,&quot;customoptions&quot;:15,&quot;options&quot;:1024,&quot;usertitle&quot;:&quot;Influencer&quot;,&quot;customtitle&quot;:&quot;Influencer&quot;,&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;content&quot;:&quot;&lt;p&gt;Thanks \u200b&lt;user-mention data-id=\&quot;43\&quot;&gt;@Rick Vanover&lt;\/user-mention&gt;\u00a0This is a solid step toward proactive ransomware defense.&lt;\/p&gt;&quot;,&quot;likes&quot;:[],&quot;attachments&quot;:[],&quot;visible&quot;:true,&quot;ipAddress&quot;:&quot;&quot;,&quot;creationDate&quot;:&quot;2025-08-17T13:31:26+0000&quot;,&quot;isHighlighted&quot;:false,&quot;isPinned&quot;:false}],&quot;totalRepliesPageCount&quot;:1,&quot;repliesAuthorSettingMap&quot;:{&quot;Chris.Childerhose&quot;:{&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;coolsport00&quot;:{&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;Rick Vanover&quot;:{&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;JMeixner&quot;:{&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;BertrandFR&quot;:{&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;Scott&quot;:{&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;JMousqueton&quot;:{&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;Link State&quot;:{&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;Tim Dressel&quot;:{&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;damien commenge&quot;:{&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;mmalarino&quot;:{&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;Filik&quot;:{&quot;showBadges&quot;:true,&quot;showReputation&quot;:true},&quot;waqasali&quot;:{&quot;showBadges&quot;:true,&quot;showReputation&quot;:true}},&quot;totalRepliesCount&quot;:16,&quot;canUserMarkBestAnswer&quot;:false,&quot;currentSort&quot;:&quot;dateline.asc&quot;}}'>
    <!-- Fallback content - shown while Preact component loads -->
    <div class="js-fallback-content">
        <div class="box__content">
            <div class="box"><div class="post__content js-content--original qa-topic-post-content post__content--new-editor" data-helper="gallery" data-data='{"delegate": "img:not([src*=\"emojione\"]), a.fancybox img", "type": "image"}'>
            <p>Now that V12.1 is available, I wanted to share with you a featured YARA rule set that can give you on-demand scanning for some top ransomware threats. </p><p>Attached to this post is a file named: <strong>Top10RW_YARArules.zip. </strong>In this file are YARA rules for some common ransomware threats that have been seen recently:</p><figure><img alt="" src="https://uploads-eu-west-1.insided.com/veeam-en/attachment/ce329148-f5a6-44c7-8783-38e12576b60f.png" /></figure><p><strong>Attribution: </strong>This great collection was made by Felix Bilsten. Links: X: <a href="https://twitter.com/fxb_b" target="_blank" rel="noreferrer noopener">Felix Bilstein (@fxb_b) / X (twitter.com)</a>, website: <a href="https://cocacoding.com/" target="_blank" rel="noreferrer noopener">Felix Bilstein - project overview (cocacoding.com)</a> and Github: <a href="https://github.com/fxb-cocacoding" target="_blank" rel="noreferrer noopener">fxb-cocacoding (Felix Bilstein) · GitHub</a></p>
        </div>
            </div>
            <div class="box">
                    <div class="pagination">
        <div class="pages"><span class="pagination-current">Page 1&nbsp;/&nbsp;1 </span></div>    </div>
                                    <div class="post box__pad qa-topic-post-box" data-helper="gallery" data-data='{"delegate": "img:not([src*=\"emojione\"]), a.fancybox img", "type": "image"}'>
            <p>Thanks for sharing these, Rick.  Looking forward to exploring Yara with 12.1.</p>
                <hr class="seperator m-b-0 ">
    </div>
                                    <div class="post box__pad qa-topic-post-box" data-helper="gallery" data-data='{"delegate": "img:not([src*=\"emojione\"]), a.fancybox img", "type": "image"}'>
            <p>Fantastic Rick! Appreciate the share. Will look at this for sure after I get my environment upgraded.</p>
                <hr class="seperator m-b-0 ">
    </div>
                                    <div class="post box__pad qa-topic-post-box" data-helper="gallery" data-data='{"delegate": "img:not([src*=\"emojione\"]), a.fancybox img", "type": "image"}'>
            <p>Cheers, Shane.</p>
                <hr class="seperator m-b-0 ">
    </div>
                                    <div class="post box__pad qa-topic-post-box" data-helper="gallery" data-data='{"delegate": "img:not([src*=\"emojione\"]), a.fancybox img", "type": "image"}'>
            <p>Thanks Rick, I will try this on Monday 😎👍🏼</p>
                <hr class="seperator m-b-0 ">
    </div>
                                    <div class="post box__pad qa-topic-post-box" data-helper="gallery" data-data='{"delegate": "img:not([src*=\"emojione\"]), a.fancybox img", "type": "image"}'>
            <p>Thanks for sharing <user-mention data-id="43">@Rick Vanover</user-mention> , any comments about it <user-mention data-id="215">@Julien Mousqueton</user-mention> ?</p>
                <hr class="seperator m-b-0 ">
    </div>
                                    <div class="post box__pad qa-topic-post-box" data-helper="gallery" data-data='{"delegate": "img:not([src*=\"emojione\"]), a.fancybox img", "type": "image"}'>
            <p>This is great. I’ll add it to the lab this week!</p>
                <hr class="seperator m-b-0 ">
    </div>
                                    <div class="post box__pad qa-topic-post-box" data-helper="gallery" data-data='{"delegate": "img:not([src*=\"emojione\"]), a.fancybox img", "type": "image"}'>
            <p><user-mention data-id="43">@Rick Vanover</user-mention> &amp; <user-mention data-id="227">@BertrandFR</user-mention> </p><p>Find bellow the golden mine of Yara rules : </p><p><a href="https://yarahq.github.io" target="_blank" rel="noreferrer noopener nofollow ugc">https://yarahq.github.io</a><br /> </p><p>“YARA Forge specializes in delivering high-quality YARA rule packages for immediate integration into security platforms. This tool automates the sourcing, standardization, and optimization of YARA rules from a variety of public repositories shared by different organizations and individuals. By collating these community-contributed rules, YARA Forge ensures that each package meets rigorous quality standards, offering a diverse and comprehensive rule set.” </p>
                <hr class="seperator m-b-0 ">
    </div>
                                    <div class="post box__pad qa-topic-post-box" data-helper="gallery" data-data='{"delegate": "img:not([src*=\"emojione\"]), a.fancybox img", "type": "image"}'>
            <p>Thank you <user-mention data-id="43">@Rick Vanover</user-mention>  everything seems okay.</p><p>uploaded C:\Program Files\Veeam\Backup and Replication\Backup\YaraRules</p><p>Launched scan yara medusa no error at the moment.<br />Thanks for sharing.</p><p> </p><figure><img alt="" src="https://uploads-eu-west-1.insided.com/veeam-en/attachment/cb47ff34-9633-420a-bbde-add3ee46f10a.png" /></figure><p> </p>
                <hr class="seperator m-b-0 ">
    </div>
                                    <div class="post box__pad qa-topic-post-box" data-helper="gallery" data-data='{"delegate": "img:not([src*=\"emojione\"]), a.fancybox img", "type": "image"}'>
            <p>Tested in my lab and it worked great. (minimal CPU available and a pretty small backup set)</p><p>I’m excited to get more into Yara rules and look forward to posting some writeups and new rules for people to try on here. </p>
                <hr class="seperator m-b-0 ">
    </div>
                                    <div class="post box__pad qa-topic-post-box" data-helper="gallery" data-data='{"delegate": "img:not([src*=\"emojione\"]), a.fancybox img", "type": "image"}'>
            <content-quote data-username="JMousqueton"><div class="content-quote-content">	<p><user-mention data-id="43">@Rick Vanover</user-mention> &amp; <user-mention data-id="227">@BertrandFR</user-mention> </p>	<p>Find bellow the golden mine of Yara rules : </p>	<p><a href="https://yarahq.github.io" rel="noreferrer noopener nofollow ugc" target="_blank">https://yarahq.github.io</a><br />	 </p>	<p>“YARA Forge specializes in delivering high-quality YARA rule packages for immediate integration into security platforms. This tool automates the sourcing, standardization, and optimization of YARA rules from a variety of public repositories shared by different organizations and individuals. By collating these community-contributed rules, YARA Forge ensures that each package meets rigorous quality standards, offering a diverse and comprehensive rule set.” </p>	</div></content-quote><p>Trying the core ruleset tonight!</p>
                <hr class="seperator m-b-0 ">
    </div>
                                    <div class="post box__pad qa-topic-post-box" data-helper="gallery" data-data='{"delegate": "img:not([src*=\"emojione\"]), a.fancybox img", "type": "image"}'>
            <p>Hello,</p><p> </p><p>Thanks for sharing it <user-mention data-id="43">@Rick Vanover</user-mention> </p><p>I’m sorry but I ‘m not sure to understand really what YARA rules are for ? </p><p>I need to select 1 rule like “test eicar” for VBR to scan file backup and say me yes there is eicar on this file backup ?</p><p>I’m sorry I don’t know anything about it but not sure I understand the benefits when I compare to other new 12.1 feature like inline detection (I don’t have to create any rules) or suspicious activity detection ?<br />Thanks for your explanations :)</p>
                <hr class="seperator m-b-0 ">
    </div>
                                    <div class="post box__pad qa-topic-post-box" data-helper="gallery" data-data='{"delegate": "img:not([src*=\"emojione\"]), a.fancybox img", "type": "image"}'>
            <p>The yara file adonunix alerts a lot of false positives, primarily it detects windows update packages as threats. Is this supposed to happen, or I should worry about it?</p><p> </p><p> </p>
                <hr class="seperator m-b-0 ">
    </div>
                                    <div class="post box__pad qa-topic-post-box" data-helper="gallery" data-data='{"delegate": "img:not([src*=\"emojione\"]), a.fancybox img", "type": "image"}'>
            <content-quote data-username="mmalarino"><div class="content-quote-content">	<p>The yara file adonunix alerts a lot of false positives, primarily it detects windows update packages as threats. Is this supposed to happen, or I should worry about it?</p>	<p> </p>	<p> </p>	</div></content-quote><p>Hi <user-mention data-id="21163">@mmalarino</user-mention> → Yes, windows update have also hit a lot of false positive for massive encryptions also. We are tuning the logic often. Stay tuned. And welcome to the Veeam community :)</p>
                <hr class="seperator m-b-0 ">
    </div>
                                    <div class="post box__pad qa-topic-post-box" data-helper="gallery" data-data='{"delegate": "img:not([src*=\"emojione\"]), a.fancybox img", "type": "image"}'>
            <p><user-mention data-id="43">@Rick Vanover</user-mention> thanks for the rules and the chance for a test. I'll be looking forward for more info!</p>
                <hr class="seperator m-b-0 ">
    </div>
                                    <div class="post box__pad qa-topic-post-box" data-helper="gallery" data-data='{"delegate": "img:not([src*=\"emojione\"]), a.fancybox img", "type": "image"}'>
            <p>Thanks Rick, I was looking for something like this.<br /><br />I went and merged all of the 10 rules from the zip in one single .yar file, so its one entry to select it and wait for the scan outcome.</p>
                <hr class="seperator m-b-0 ">
    </div>
                                    <div class="post box__pad qa-topic-post-box" data-helper="gallery" data-data='{"delegate": "img:not([src*=\"emojione\"]), a.fancybox img", "type": "image"}'>
            <p>Thanks ​<user-mention data-id="43">@Rick Vanover</user-mention> This is a solid step toward proactive ransomware defense.</p>
                <hr class="seperator m-b-0 ">
    </div>
                            </div>
        </div>
    </div>
</div>        
                                                                <div class="box box__pad">
                        
<div
        data-preact="topic-list-view/TopicAddReply"
        data-props='{&quot;disableFileAttachments&quot;:true,&quot;isGuest&quot;:true,&quot;type&quot;:&quot;article&quot;,&quot;topicId&quot;:6267,&quot;redirect&quot;:true,&quot;isControl&quot;:false,&quot;showGroupJoin&quot;:true,&quot;placeholder&quot;:&quot;topic.reply.placeholder.textarea&quot;}'
></div>
                    </div>
                                                </div>
        </div>
    </div>

            <div class="col  col--side  Sidebar qa-div-sidebar custom-sidebar">
                                      <div class="module Sidebarmodule">
                                                                                                
            <div data-preact="related-topics/RelatedTopics"
     data-props="{&quot;widgetTitle&quot;:&quot;Related topics&quot;,&quot;pageSize&quot;:&quot;5&quot;}">
</div>

<div data-preact="widget-notification/FeaturedTopicsWrapper" class="" data-props="{&quot;widget&quot;:&quot;featuredSide&quot;}"></div>

        </div>
                        </div>
    
    </div>
</div>
<div class="full-width Template-secondary">
    <div class="sitewidth">

                                        <div class="col col--main has--side">
                                                        </div>
            
        
    </div>
</div>
<div class="full-width Template-footer">

                                    <div data-preact="powered-by-insided/index" class="powered-by-insided-footer" data-props="{&quot;rootUrl&quot;:&quot;community.veeam.com&quot;,&quot;termsConditions&quot;:&quot;\/site\/terms&quot;,&quot;cookieConfig&quot;:{&quot;use_external_modal&quot;:false,&quot;mapping&quot;:{&quot;required&quot;:1,&quot;anonymous&quot;:2,&quot;all&quot;:3}},&quot;communityVisibility&quot;:&quot;public&quot;,&quot;isGuestUser&quot;:true,&quot;phrases&quot;:{&quot;Forum&quot;:{&quot;branded.back_to_top&quot;:&quot;Back to top&quot;,&quot;Terms &amp; Conditions&quot;:&quot;Terms &amp; Conditions&quot;,&quot;cookiepolicy.link&quot;:&quot;Cookie settings&quot;}}}"><div class="Template-footer"><div class="sitewidth box box--blend" data-component="scrollTopStickyButton"><div class="templatefoot"><a href="https://www.gainsight.com/customer-communities/" class="logo-gainsight" title="Visit Gainsight.com" target="_blank" rel="noreferrer" aria-label><span class="is-hidden">Powered by Gainsight</span></a></div><div class="templatefoot-privacy-links"><a href="/site/terms" aria-label="Terms &amp; Conditions">Terms &amp; Conditions</a><a href="https://www.gainsight.com/policy/accessibility-cc/" target="_blank" rel="noreferrer">Accessibility statement</a></div><button class="scroll-to-top-sticky-button js-scrollto widget--base-shadow is-hidden-S custom-scroll-to-top button-control-new button-control-new--small button-control-new--secondary" type="button" aria-label="Back to top"><div><div><span class="button-control__title-text"></span></div></div></button></div></div></div>
            
        
</div>

        
            
    <a href="/topic/new"
       aria-label="Create topic"
       data-track='{&quot;trigger&quot;:&quot;floating button&quot;,&quot;type&quot;:&quot;Topic Initiated&quot;}'
       role="button"
       class="btn--cta btn--create-topic btn--fixed btn--fixed__bottom is-visible-S qa-menu-create-topic">
        <span class="icon icon--pen icon--auto-width" aria-hidden="true"></span>
    </a>
        
<div class="modals box is-hidden js-legacy-modals">
                                    <div class="qa-register-modal" data-helper="modal" data-data='{"modal_id": "register", "mainClass": "modal--register"}' id="modal_register" >
                

    
    <label for="" >
      
    </label>



<h2>
            Sign up
    </h2>

    <p>Already have an account? <a class="js-open-modal qa-register-have-account-link"  data-modal="login">Login</a>
    </p>


<div id="modal_login" >
    
            <h4><span id="delimiter" class="Delimiter"></span> </h4>
    
    
    
    
    
    
            <a class="btn--cta btn--sso qa-sso-openid" href="https://community.veeam.com/ssoproxy/login?ssoType=openidconnect" target="_top">
            Log in with your Veeam account
        </a>
    
    
    
    
    
    
    
    
    </div>


<script type="application/javascript">
  if (document.querySelector('.email_repeat')) {
    document.querySelector('.email_repeat').style.display = 'none'
  }
    //invite tricks
    if(document.querySelector('#register_is_invite') && document.querySelector('#register_is_invite').value) {
        let name = document.querySelector('#register_user_username');
        if (name.value === '--removed--') {
            name.value = ''
        }
        let email = document.querySelector('#register_user_email')
        email.readOnly = 1
        email.classList.add('register_user_email--disabled')
    }
</script>
            </div>
        
                            <div class="qa-login-modal" data-helper="modal" data-data='{"modal_id": "login", "mainClass": "modal--login"}' id="modal_login" >
                
    <label for="">
        
    </label>

            <h2>Login to the community</h2>
    
    
    
            <h4><span id="delimiter" class="Delimiter"></span> </h4>
    
    
    
    
    
    
            <a class="btn--cta btn--sso qa-sso-openid" href="https://community.veeam.com/ssoproxy/login?ssoType=openidconnect" target="_top">
            Log in with your Veeam account
        </a>
    
    
    
    
    
    
    
    
    
                </div>
        
                <div class="qa-forgot-modal" data-helper="modal" data-data='{"modal_id": "forgot", "mainClass": "modal--forgot"}' id="modal_forgot" >
            <p>Enter your E-mail address. We'll send you an e-mail with instructions to reset your password.</p>

<form name="forgotPassword" method="post" action="/member/forgotPassword" class="form js-ajax-form--forgot" id="form--forgot__884400133">

  <div class="js-notification">
      
  </div>

      
    <div class="form__row">
        <div class="first">
                        <label class="label required" for="forgotPassword_username">
                            Enter your e-mail address
            
            
                                </label>
        </div>
        <div class="second">
                        <input type="text" id="forgotPassword_username" name="forgotPassword[username]" required="required" />

        </div>
    </div>

  <div class="form-row first">
      <button type="submit" id="forgotPassword_submit" name="forgotPassword[submit]" class="btn btn--cta qa-submit-button">
        Send
    </button>
                <a href="#" class="group__item end js-open-modal qa-forgot-password-overview-link" data-modal="login">Back to overview</a>
        </div>
            <input type="hidden" id="forgotPassword__token" name="forgotPassword[_token]" value="pQWzMmzvubNFyGAGFuptOp0Kh1WvODxctX2JHVZdUWw" />
</form>

        </div>
    
                <div class="qa-report-modal" data-helper="modal" data-data='{"modal_id": "report", "mainClass": "modal--report"}' id="modal_report" >

        </div>
    
          <div class="attachments--modal" data-helper="modal" data-data='{"modal_id": "attachments-pending-modal"}'>
        <h2>Scanning file for viruses.</h2>
        <p>Sorry, we're still checking this file's contents to make sure it's safe to download. Please try again in a few minutes.</p>
        <a href="#" class="mfp-close btn--cta">OK</a>
      </div>

      <div class="attachments--modal" data-helper="modal" data-data='{"modal_id": "attachments-infected-modal"}'>
        <h2>This file cannot be downloaded</h2>
        <p>Sorry, our virus scanner detected that this file isn't safe to download.</p>
        <a href="#" class="mfp-close btn--cta">OK</a>
      </div>
    </div>


        <script>
  window.appState = {"appName":"forum","activeHubModules":["Community","Event","Group","Ideation","KnowledgeBase","ProductUpdates"],"activeEntities":{"topic":true,"replies":true,"userRoles":true,"privateMessage":true,"transcript":false,"favorite":true,"profile":true,"search":true,"notification":true},"language":"en-US"}
</script>
        <div><script type="text/javascript">window.inSidedData = {"communityId":"veeam-en","environment":"production","language":"en","device":"desktop","params":{"skipPageview":false},"user":{"userid":null,"name":"guest","role":"roles.guest","mainRole":"roles.guest","rank":"","avatar":"","rankIcon":"","rankName":"","isModerator":false,"pmUnreadCount":0,"pmTotalCount":0,"topicsCount":0,"repliesCount":0,"solvedCount":0,"loginSource":null,"registerSource":null},"page":{"pageNumber":1,"name":"Topic","path":"veeam-en:Content:Topic:Featured YARA rule: Top 10 Ransomware Threats","section":"Content","site":"veeam-en","title":"Topic:Featured YARA rule: Top 10 Ransomware Threats","url":"/yara-and-script-library-67/featured-yara-rule-top-10-ransomware-threats-6267","firstRender":false},"form":{"name":"","step":""},"content":{"category":{"id":67,"title":"YARA and Script Library","type":"default"},"topic":{"id":6267,"title":"Featured YARA rule: Top 10 Ransomware Threats","type":"article","content_type":null,"source_id":null,"created":1702658604,"replies":16,"is_sticky":"false","prefix":null,"tags":"Featured Yara Rule"},"post":{"id":null},"path":"YARA and Script Library:Featured YARA rule: Top 10 Ransomware Threats"},"search":{"phrase":null,"count":null}}</script></div>        


        <div data-preact="cookie-banner/index" class="" data-props="{&quot;level&quot;:3,&quot;termsConditions&quot;:&quot;\/site\/terms&quot;,&quot;cookieConfig&quot;:{&quot;use_external_modal&quot;:false,&quot;mapping&quot;:{&quot;required&quot;:1,&quot;anonymous&quot;:2,&quot;all&quot;:3}},&quot;phrases&quot;:{&quot;Forum&quot;:{&quot;cookiepolicy.title&quot;:&quot;Cookie policy&quot;,&quot;cookiepolicy.content&quot;:&quot;We use cookies to enhance and personalize your experience. If you accept you agree to our full cookie policy. &lt;a href=\&quot;{link}\&quot;&gt;Learn more about our cookies.&lt;\/a&gt;&quot;,&quot;cookiepolicy.button&quot;:&quot;Accept cookies&quot;,&quot;cookiepolicy.button.deny&quot;:&quot;Deny all&quot;,&quot;cookiepolicy.link&quot;:&quot;Cookie settings&quot;,&quot;cookiepolicy.modal.title&quot;:&quot;Cookie settings&quot;,&quot;cookiepolicy.modal.content&quot;:&quot;We use 3 different kinds of cookies. You can choose which cookies you want to accept. We need basic cookies to make this site work, therefore these are the minimum you can select. &lt;a href=\&quot;{link}\&quot;&gt;Learn more about our cookies.&lt;\/a&gt;&quot;,&quot;cookiepolicy.modal.level1&quot;:&quot;Basic&lt;br&gt;Functional&quot;,&quot;cookiepolicy.modal.level2&quot;:&quot;Normal&lt;br&gt;Functional + analytics&quot;,&quot;cookiepolicy.modal.level3&quot;:&quot;Complete&lt;br&gt;Functional + analytics + social media + embedded videos + marketing&quot;}}}"></div>

        
        
        
        
                                                                                                                                    
    <div class="ssi ssi-footer custom-footer">
                    <style>
		.Template-footer {
			height:160px;
		}
</style>

            </div>
                                                                                
        <input id="csrftoken" type="hidden" value="XwwKXfMObKvh12jGVl8KZ66d43rZz6560tnaG7ZrRf4"/>

        <div data-preact="site-wide/index" class="" data-props="{}"><div></div></div>
        <div data-preact="multi-language/index" data-props='{&quot;ssoLoginUrl&quot;:&quot;https:\/\/community.veeam.com\/ssoproxy\/login?ssoType=openidconnect&quot;,&quot;loginPhrase&quot;:&quot;Login&quot;}'></div>
        <script src='https://d3odp2r1osuwn0.cloudfront.net/2025-09-30-13-23-03-037e73449a/dist/js/850.js'></script><script src='https://d3odp2r1osuwn0.cloudfront.net/2025-09-30-13-23-03-037e73449a/dist/js/95.js'></script><script src='https://d3odp2r1osuwn0.cloudfront.net/2025-09-30-13-23-03-037e73449a/dist/js/441.js'></script><script src='https://d3odp2r1osuwn0.cloudfront.net/2025-09-30-13-23-03-037e73449a/dist/js/748.js'></script><script
                crossorigin='anonymous'
                src='https://d3odp2r1osuwn0.cloudfront.net/2025-09-30-13-23-03-037e73449a/dist/js/preact-app.js'
                id='insided-preact-app'
                data-basepath='https://d3odp2r1osuwn0.cloudfront.net/2025-09-30-13-23-03-037e73449a/dist/js/'
                data-environment='production'
                data-region='eu-west-1'
                data-communityId='veeam-en'
                data-modules='["articleScheduling","CommunityOverview","convertQuestionsToIdeas","codeSnippetDarkTheme","event","eventEngagement","eventSubscriptions","group","hiddenGroup","NewUICardGroupOverview","privateGroup","ideation","ideationV2","productAreas","knowledgeBase","articleToProductUpdateConversion","productUpdates","TopicSocialShare","automationRules","adminSeats","aiFeatures","aiFeaturesForCM","aiFeedback","aiModeratorKit","aiEvolutionModerationWidget","unifiedIndexEnabled","analyticsExport","analyticsMetadata","analyticsV2","analyticsV2ProductFeedback","analyticsV2SelfService","badges","biToolsConnector","ccRebranding","categorySettings","changeAuthorOfPublishedContent","channelConfiguration","contentHelpfulness","contentInPreferredLanguage","contacts","conversationalWidget","controlSideMenu","customCss","customPages","customPagesDuplication","customizationSettings","destinationCustomization","disableRegistrationSpamCheck","draftContent","emailCampaigns","emailSuppression","emailTemplate","enableGroupTags","engagementDashboard","emoji","experimentalFeatures","fileAttachments","freshdeskV2","gainsightPlatformSso","showHAToggle","haCookielessAuth","imageResizingAndAlignment","integrationsApi","integrationsApps","intercomCreateConversations","intercomFederatedSearch","leaderboardPage","loginWithEmail","mentions","metadataPostDetails","metadataSettings","moderationHome","moderationLabels","moderationNotifications","moderationOverview","moderationOverviewBetaDefault","multiLanguage","localizedHomepage","nonModeratorsCanUploadImagesAndVideos","pageConfiguration","platformVisibility","pointSystem","preModerationRules","privateMessage","productboardIntegration","publicTagAutoSuggestion","publicTagDestination","publicTagManagement","rank","registrationRules","reportPrivateMessages","reputation","richTopicCards","salesforceSyncAccountData","searchRevamp","searchRevampForAllRoles","selfBadges","selfServiceSSO","seoManagement","skilljarFederatedSearch","spamContent","spamPrevention","subforumSubscription","systemEmails","teamNotes","thirdPartyScripts","thoughtIndustries","trackingEnabled","topicsCreate","translations","userGroups","userOverview","userOverviewStatistics","userProfileFields","userProfileOverview","userRoles","userSegments","unreadPostCounter","webmasterManagement","widgetPersonalisation","widgetSiteIdentity","widgetsSettings","zendeskFederatedSearch","zendeskTicketEscalation","zapier","allowCdnCaching"]'
                data-userPermissions='{"readableCategories":[],"permissions":["forum-product-updates-all"]}'
                data-cssLink='https://d3odp2r1osuwn0.cloudfront.net/2025-09-30-13-23-03-037e73449a/dist/css/preact-app.css'
                data-defaultCdn=''
                data-fb-app-id=''
                data-communityUrl='https://community.veeam.com'
                data-controlUrl='https://veeam-en.insided.com'
                data-eventLogger='https://o9tt6h08li.execute-api.eu-west-1.amazonaws.com/v1/event'
                data-application='forum'
                data-cookieConfig='{"use_external_modal":false,"mapping":{"required":1,"anonymous":2,"all":3}}'
                data-defaultCookieLevel='3'
                nonce=''
                data-search='{"client_id":"IC23ZXNZKT","token":"YjQ0ZGI3YzFlY2I5NjA1NzAxZmU2OTE0ZjBkMTE4NDQ1NTU3OThjMzIyYjJlZjY3NzE3Nzg1ODVjM2U3ODE2NmZpbHRlcnM9Zm9ydW0lM0ErMStPUitmb3J1bSUzQSsxMDErT1IrZm9ydW0lM0ErMTIxK09SK2ZvcnVtJTNBKzEyNCtPUitmb3J1bSUzQSsxMjYrT1IrZm9ydW0lM0ErMTI3K09SK2ZvcnVtJTNBKzEyOCtPUitmb3J1bSUzQSsxMzArT1IrZm9ydW0lM0ErMTMxK09SK2ZvcnVtJTNBKzEzMitPUitmb3J1bSUzQSsxMzMrT1IrZm9ydW0lM0ErMTM3K09SK2ZvcnVtJTNBKzE0MStPUitmb3J1bSUzQSsxNDcrT1IrZm9ydW0lM0ErMTUwK09SK2ZvcnVtJTNBKzE2MytPUitmb3J1bSUzQSsxNjcrT1IrZm9ydW0lM0ErMTY4K09SK2ZvcnVtJTNBKzE3MCtPUitmb3J1bSUzQSsxNzErT1IrZm9ydW0lM0ErMTczK09SK2ZvcnVtJTNBKzE3NStPUitmb3J1bSUzQSsxNzYrT1IrZm9ydW0lM0ErMTc3K09SK2ZvcnVtJTNBKzE3OStPUitmb3J1bSUzQSsxODIrT1IrZm9ydW0lM0ErMTg1K09SK2ZvcnVtJTNBKzE4NitPUitmb3J1bSUzQSsxODcrT1IrZm9ydW0lM0ErMjIrT1IrZm9ydW0lM0ErNDArT1IrZm9ydW0lM0ErNStPUitmb3J1bSUzQSs1MCtPUitmb3J1bSUzQSs1NitPUitmb3J1bSUzQSs1NytPUitmb3J1bSUzQSs1OCtPUitmb3J1bSUzQSs1OStPUitmb3J1bSUzQSs2NitPUitmb3J1bSUzQSs2NytPUitmb3J1bSUzQSs2OStPUitmb3J1bSUzQSs5K09SK2ZvcnVtJTNBKzI3K09SK2ZvcnVtJTNBKzUzK09SK2ZvcnVtJTNBKzYwK09SK2ZvcnVtJTNBKzYxK09SK2ZvcnVtJTNBKzYyK09SK2ZvcnVtJTNBKzYzK09SK2ZvcnVtJTNBKzY1K09SK2ZvcnVtJTNBKzcyK09SK2ZvcnVtJTNBKzczK09SK2ZvcnVtJTNBKzc1K09SK2ZvcnVtJTNBKzc2K09SK2ZvcnVtJTNBKzc3K09SK2ZvcnVtJTNBKzc4K09SK2ZvcnVtJTNBKzc5K09SK2ZvcnVtJTNBKzgxK09SK2ZvcnVtJTNBKzgyK09SK2ZvcnVtJTNBKzg0K09SK2ZvcnVtJTNBKzg1K09SK2ZvcnVtJTNBKzkwK09SK2ZvcnVtJTNBKzkxK09SK2ZvcnVtJTNBKzkyK09SK2ZvcnVtJTNBKzkzK09SK2ZvcnVtJTNBKzk0K09SK2ZvcnVtJTNBKzk1K09SK2ZvcnVtJTNBKzk2K09SK2ZvcnVtJTNBKzk4K09SK2ZvcnVtJTNBKzEwMytPUitmb3J1bSUzQSsxMDQrT1IrZm9ydW0lM0ErMTA3K09SK2ZvcnVtJTNBKzExMStPUitmb3J1bSUzQSsxMTQrT1IrZm9ydW0lM0ErMTE1K09SK2ZvcnVtJTNBKzExOCtPUitmb3J1bSUzQSsxMjArT1IrZm9ydW0lM0ErMTM0K09SK2ZvcnVtJTNBKzEzNStPUitmb3J1bSUzQSsxMzYrT1IrZm9ydW0lM0ErMTQ4K09SK2ZvcnVtJTNBKzE0OStPUitmb3J1bSUzQSsxNTErT1IrZm9ydW0lM0ErMTUyK09SK2ZvcnVtJTNBKzE1NCtPUitmb3J1bSUzQSsxNjArT1IrZm9ydW0lM0ErMTYxK09SK2ZvcnVtJTNBKzE4MStPUitwdWJsaWNfcmVjb3JkJTNBdHJ1ZStPUitjb250ZW50X3R5cGUlM0Fwcm9kdWN0VXBkYXRlJnJlc3RyaWN0SW5kaWNlcz12ZWVhbS1lbiUyQSZxdWVyeUxhbmd1YWdlcz0lNUIlMjJlbiUyMiU1RCZ2YWxpZFVudGlsPTE3NTkyNzMwODA=","basicToken":"Y2RkZThhNTdjYTg4MzAyYWM1NTQyMGY2Y2E1YzRmMmViN2E2ODI3ZTViNDgwNmM5MDMyY2IwMjk3OGEwYjNmZmZpbHRlcnM9cHVibGljX3JlY29yZCUzQXRydWUmcmVzdHJpY3RJbmRpY2VzPXZlZWFtLWVuJTJBJnF1ZXJ5TGFuZ3VhZ2VzPSU1QiUyMmVuJTIyJTVEJnZhbGlkVW50aWw9MTc1OTI3MzA4MA==","isZendeskFederatedSearchEnabled":false,"hiddenCategories":["141"],"unifiedIndexEnabled":true}'
                data-selectedCookieLevel='3'></script>
        <script src='https://d3odp2r1osuwn0.cloudfront.net/2025-09-30-13-23-03-037e73449a/dist/js/850.js'></script><script src='https://d3odp2r1osuwn0.cloudfront.net/2025-09-30-13-23-03-037e73449a/dist/js/729.js'></script><script src='https://d3odp2r1osuwn0.cloudfront.net/2025-09-30-13-23-03-037e73449a/dist/js/441.js'></script><script src="https://d3odp2r1osuwn0.cloudfront.net/2025-09-30-13-23-03-037e73449a/dist/js/app.js" id="insided-app"  data-basepath="https://d3odp2r1osuwn0.cloudfront.net/2025-09-30-13-23-03-037e73449a/dist/js/" nonce="" data-environment="production" data-region="eu-west-1" data-communityId="veeam-en" data-modules='["articleScheduling","CommunityOverview","convertQuestionsToIdeas","codeSnippetDarkTheme","event","eventEngagement","eventSubscriptions","group","hiddenGroup","NewUICardGroupOverview","privateGroup","ideation","ideationV2","productAreas","knowledgeBase","articleToProductUpdateConversion","productUpdates","TopicSocialShare","automationRules","adminSeats","aiFeatures","aiFeaturesForCM","aiFeedback","aiModeratorKit","aiEvolutionModerationWidget","unifiedIndexEnabled","analyticsExport","analyticsMetadata","analyticsV2","analyticsV2ProductFeedback","analyticsV2SelfService","badges","biToolsConnector","ccRebranding","categorySettings","changeAuthorOfPublishedContent","channelConfiguration","contentHelpfulness","contentInPreferredLanguage","contacts","conversationalWidget","controlSideMenu","customCss","customPages","customPagesDuplication","customizationSettings","destinationCustomization","disableRegistrationSpamCheck","draftContent","emailCampaigns","emailSuppression","emailTemplate","enableGroupTags","engagementDashboard","emoji","experimentalFeatures","fileAttachments","freshdeskV2","gainsightPlatformSso","showHAToggle","haCookielessAuth","imageResizingAndAlignment","integrationsApi","integrationsApps","intercomCreateConversations","intercomFederatedSearch","leaderboardPage","loginWithEmail","mentions","metadataPostDetails","metadataSettings","moderationHome","moderationLabels","moderationNotifications","moderationOverview","moderationOverviewBetaDefault","multiLanguage","localizedHomepage","nonModeratorsCanUploadImagesAndVideos","pageConfiguration","platformVisibility","pointSystem","preModerationRules","privateMessage","productboardIntegration","publicTagAutoSuggestion","publicTagDestination","publicTagManagement","rank","registrationRules","reportPrivateMessages","reputation","richTopicCards","salesforceSyncAccountData","searchRevamp","searchRevampForAllRoles","selfBadges","selfServiceSSO","seoManagement","skilljarFederatedSearch","spamContent","spamPrevention","subforumSubscription","systemEmails","teamNotes","thirdPartyScripts","thoughtIndustries","trackingEnabled","topicsCreate","translations","userGroups","userOverview","userOverviewStatistics","userProfileFields","userProfileOverview","userRoles","userSegments","unreadPostCounter","webmasterManagement","widgetPersonalisation","widgetSiteIdentity","widgetsSettings","zendeskFederatedSearch","zendeskTicketEscalation","zapier","allowCdnCaching"]' data-cssLink='https://d3odp2r1osuwn0.cloudfront.net/2025-09-30-13-23-03-037e73449a/dist/css/preact-app.css' data-defaultCdn='https://d3odp2r1osuwn0.cloudfront.net/2025-09-30-13-23-03-037e73449a/control/assets' data-fb-app-id='' data-language='en'></script><script nonce="">app.init([{"model":"csrf","data":{"name":"yip_csrf_token","token":"XwwKXfMObKvh12jGVl8KZ66d43rZz6560tnaG7ZrRf4"}},{"el":"head","component":"google-analytics","data":{"tokens":[{"token":"UA-186027832-1","name":"insided","verification":""}],"privacyLevel":3,"nonce":""}},{"el":".js-ajax-form--registration","component":"ajax-form"},{"el":"#form--forgot__884400133","component":"ajax-form"},{"el":".js-open-modal","helper":"show-modal"},{"data":{"map":null,"breadcrumbData":[{"title":"Community","url":"\/"},{"title":"Community","url":"\/community-40"},{"title":"YARA and Script Library","url":"\/yara-and-script-library-67"},{"title":"Featured YARA rule: Top 10 Ransomware Threats","url":"\/yara-and-script-library-67\/featured-yara-rule-top-10-ransomware-threats-6267"}]},"component":"tracker"},{"el":"body","helper":"collapse"},{"el":"body","helper":"ajax-link"},{"model":"global_translations","data":{"ajax-form":{"connection_error":"Unable to submit form. Please refresh the page and try again."},"modal":{"close":"Close","loading":"Loading","gallery_previous":"Previous","gallery_next":"Next","gallery_counter":"%curr% of %total%","image_error":"The image could not be loaded","content_error":"The content could not be loaded"}}},{"view":"MainNavigation","el":".js-main-navigation"}]);</script>
                    
            <script type="text/javascript" nonce="">window.NREUM||(NREUM={});NREUM.info={"beacon":"bam.nr-data.net","licenseKey":"5364be9000","applicationID":"523907688,438605444,16947947","transactionName":"YgFTY0QFW0sHUkVQWVtLcFRCDVpWSXhfal9RAVVrdQtbTBReXVVTRzh3WEQRWGQyXkFQVXYLX0NEC1lUA0MeSl5aEw==","queueTime":0,"applicationTime":306,"atts":"TkZEFQwfSBREUBMDTUgZ","errorBeacon":"bam.nr-data.net","agent":""}</script>        
        
    </main>

<!--Start Cookie Script -->
<script type="text/javascript" charset="UTF-8" src="//eu.cookie-script.com/s/c00efc3f5063e4652fc59760abf306d1.js"></script>
<!--End Cookie Script-->

<script>
  document.querySelector("div.header-navigation_logo-wrapper.is-hidden-L > a").href = '/'
</script>



<script src="https://d3odp2r1osuwn0.cloudfront.net/2025-09-30-13-23-03-037e73449a/control/assets/common/js/jquery.yiiactiveform.js" nonce=""></script>

</body>
</html>
