(function(){
"use strict";
var root=document.documentElement;
root.classList.add("js-motion");
var language="ko";
function syncMenuLabel(){
 var button=document.querySelector("[data-menu-toggle]");
 if(!button)return;
 var open=button.getAttribute("aria-expanded")==="true";
 button.setAttribute("aria-label",language==="ko"?(open?"메뉴 닫기":"메뉴 열기"):(open?"Close menu":"Open menu"));
}
function applyLanguage(next){
 language=next==="en"?"en":"ko";
 root.lang=language;
 document.querySelectorAll("[data-ko][data-en]").forEach(function(el){
   el.innerHTML=language==="ko"?el.getAttribute("data-ko"):el.getAttribute("data-en");
 });
 document.querySelectorAll("[data-placeholder-ko][data-placeholder-en]").forEach(function(el){
   el.placeholder=language==="ko"?el.getAttribute("data-placeholder-ko"):el.getAttribute("data-placeholder-en");
 });
 document.querySelectorAll("[data-lang-button]").forEach(function(btn){
   btn.classList.toggle("active",btn.getAttribute("data-lang-button")===language);
   btn.setAttribute("aria-pressed",btn.getAttribute("data-lang-button")===language?"true":"false");
 });
 syncMenuLabel();
 syncDemoLanguage();
 try{sessionStorage.setItem("custos-language",language)}catch(e){}
}
try{var saved=sessionStorage.getItem("custos-language");if(saved==="en")language="en"}catch(e){}
document.querySelectorAll("[data-lang-button]").forEach(function(btn){btn.addEventListener("click",function(){applyLanguage(btn.getAttribute("data-lang-button"))})});
applyLanguage(language);
var toggle=document.querySelector("[data-menu-toggle]");
var mobile=document.querySelector("[data-mobile-nav]");
if(toggle&&mobile){
 toggle.addEventListener("click",function(){
  var open=mobile.classList.toggle("open");
  toggle.setAttribute("aria-expanded",open?"true":"false");
  syncMenuLabel();
 });
 mobile.querySelectorAll("a").forEach(function(a){a.addEventListener("click",function(){mobile.classList.remove("open");toggle.setAttribute("aria-expanded","false");syncMenuLabel()})});
 document.addEventListener("keydown",function(event){
  if(event.key==="Escape"&&mobile.classList.contains("open")){
   mobile.classList.remove("open");toggle.setAttribute("aria-expanded","false");syncMenuLabel();toggle.focus();
  }
 });
}
var page=document.body.getAttribute("data-page");
document.querySelectorAll("[data-nav]").forEach(function(a){
 if(a.getAttribute("data-nav")===page){a.classList.add("active");a.setAttribute("aria-current","page")}
});
if("IntersectionObserver" in window){
 var observer=new IntersectionObserver(function(entries){
  entries.forEach(function(entry){if(entry.isIntersecting){entry.target.classList.add("visible");observer.unobserve(entry.target)}});
 },{threshold:.08});
 document.querySelectorAll(".reveal").forEach(function(el){observer.observe(el)});
}else{document.querySelectorAll(".reveal").forEach(function(el){el.classList.add("visible")})}
var cases={
 read:{action:"read_database",resource:"research_db",scope:"READ ONLY",effect:"NONE / MOCK",decision:"ALLOW",tone:"allow",ko:"요청된 행동과 리소스가 정책 범위에 포함됩니다. 모의 실행 단계로 진행할 수 있습니다.",en:"The requested action and resource match the configured policy. The mock execution step may proceed."},
 email:{action:"send_email",resource:"company_email",scope:"HUMAN REVIEW",effect:"EXTERNAL ACTION",decision:"HUMAN_APPROVAL",tone:"approval",ko:"외부로 이메일을 보내는 행동은 사람의 명시적 승인이 필요합니다. 승인 전에는 실행되지 않습니다.",en:"Sending an email is a gated action. It remains paused until an authorized reviewer approves the exact request."},
 disable:{action:"disable_custos",resource:"custos_core",scope:"PROTECTED ACTION",effect:"SYSTEM INTEGRITY",decision:"BLOCK",tone:"block",ko:"통제 시스템 비활성화는 보호 대상 행동입니다. 요청이 차단되며 실행되지 않습니다.",en:"Disabling the control layer is a protected action. The policy blocks the request before execution."}
};
var selected="read",pending=false,demoState="idle";
function syncDemoLanguage(){
 if(typeof cases==="undefined"||typeof selected==="undefined"||typeof demoState==="undefined")return;
 var c=cases[selected];if(!c)return;
 var decision=document.getElementById("demoDecision"),dot=document.getElementById("demoLed"),desc=document.getElementById("demoDescription"),review=document.getElementById("demoReview");
 if(!decision||!dot||!desc)return;
 if(demoState==="idle"){
  decision.textContent=language==="ko"?"판정 대기":"AWAITING DECISION";
  dot.className="decision-led";
  desc.textContent=language==="ko"?"시나리오를 선택하고 정책 판정을 실행하세요.":"Select a scenario and run the policy check.";
 }else if(demoState==="approved"){
  decision.textContent=language==="ko"?"승인됨 · 모의 실행":"APPROVED · MOCK";
  dot.className="decision-led allow";
  desc.textContent=language==="ko"?"사람이 승인했습니다. 이 데모는 모의 실행만 표시합니다.":"A human approved the request. This demo shows mock execution only.";
 }else if(demoState==="denied"){
  decision.textContent=language==="ko"?"거부됨 · 실행 차단":"DENIED · BLOCKED";
  dot.className="decision-led block";
  desc.textContent=language==="ko"?"사람이 거부했습니다. 요청은 실행되지 않습니다.":"A human denied the request. The action remains unexecuted.";
 }else{
  var labels={ALLOW:language==="ko"?"허용":"ALLOW",HUMAN_APPROVAL:language==="ko"?"인간 승인 필요":"HUMAN APPROVAL REQUIRED",BLOCK:language==="ko"?"차단":"BLOCK"};
  decision.textContent=labels[c.decision]||c.decision;
  dot.className="decision-led "+c.tone;
  desc.textContent=language==="ko"?c.ko:c.en;
 }
 if(review){review.hidden=!pending;review.classList.toggle("show",pending);}
}
function pick(id){
 selected=id;pending=false;demoState="idle";
 document.querySelectorAll("[data-demo-case]").forEach(function(b){var active=b.getAttribute("data-demo-case")===id;b.classList.toggle("active",active);b.setAttribute("aria-pressed",active?"true":"false")});
 var c=cases[id];if(!c)return;
 var action=document.getElementById("demoAction"),resource=document.getElementById("demoResource"),scope=document.getElementById("demoScope"),effect=document.getElementById("demoEffect"),decision=document.getElementById("demoDecision"),dot=document.getElementById("demoLed"),desc=document.getElementById("demoDescription"),review=document.getElementById("demoReview");
 if(!action)return;
 action.textContent=c.action;resource.textContent=c.resource;scope.textContent=c.scope;effect.textContent=c.effect;
 decision.textContent=language==="ko"?"판정 대기":"AWAITING DECISION";dot.className="decision-led";desc.textContent=language==="ko"?"시나리오를 선택하고 정책 판정을 실행하세요.":"Select a scenario and run the policy check.";
 if(review){review.classList.remove("show");review.hidden=true;}
 syncDemoLanguage();
}
document.querySelectorAll("[data-demo-case]").forEach(function(b){b.addEventListener("click",function(){pick(b.getAttribute("data-demo-case"))})});
var run=document.querySelector("[data-demo-run]");
if(run)run.addEventListener("click",function(){
 var c=cases[selected];if(!c)return;
 demoState="decision";
 document.getElementById("demoDecision").textContent=c.decision;
 document.getElementById("demoLed").className="decision-led "+c.tone;
 document.getElementById("demoDescription").textContent=language==="ko"?c.ko:c.en;
 var review=document.getElementById("demoReview");pending=c.decision==="HUMAN_APPROVAL";
 if(review){review.hidden=!pending;review.classList.toggle("show",pending);}
 syncDemoLanguage();
});
function reviewDemo(decision){
 if(!pending)return;
 var approved=decision==="approve";demoState=approved?"approved":"denied";
 document.getElementById("demoDecision").textContent=approved?(language==="ko"?"승인됨 · 모의 실행":"APPROVED · MOCK"):(language==="ko"?"거부됨 · 실행 차단":"DENIED · BLOCKED");
 document.getElementById("demoLed").className="decision-led "+(approved?"allow":"block");
 document.getElementById("demoDescription").textContent=language==="ko"?(approved?"사람이 승인했습니다. 이 데모는 모의 실행만 표시합니다.":"사람이 거부했습니다. 요청은 실행되지 않습니다."):(approved?"A human approved the request. This demo shows mock execution only.":"A human denied the request. The action remains unexecuted.");
 document.getElementById("demoReview").classList.remove("show");document.getElementById("demoReview").hidden=true;pending=false;
 syncDemoLanguage();
}
var approve=document.querySelector("[data-demo-approve]"),deny=document.querySelector("[data-demo-deny]");
if(approve)approve.addEventListener("click",function(){reviewDemo("approve")});
if(deny)deny.addEventListener("click",function(){reviewDemo("deny")});
if(document.querySelector("[data-demo-case]"))pick("read");
})();