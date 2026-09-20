import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runTool } from '../supabase/functions/chat/tools.ts';
import { labourResult } from '../supabase/functions/chat/labour-totals.ts';
import { callerProfile, resolveDisplayName } from '../supabase/functions/chat/profile.ts';

const row = (vintage, period_month, job_category, labor_hours, labor_cost, expense_cost) => ({vintage, period_month, job_category, labor_hours, labor_cost, expense_cost});
const monthly = [row(2026,'2026-07-01','Canopy','581.24','29331.39','4346.092800000000316'), row(2026,'2026-08-01','Canopy','300','18000','0'), row(2026,'2026-08-01','Irrigation','65.19','2281.18','5531.16480000000038')];
const coverage = [{vintage:2026,first_month:'2026-07-01',last_month:'2026-08-01',month_count:2}];
function db(tables, errors = {}) {
  const calls=[];
  return {calls, from(table) {
    let rows=tables[table]??[]; calls.push(['from',table]);
    const q={select(s){calls.push(['select',s]); return q},eq(k,v){calls.push(['eq',k,v]);rows=rows.filter(r=>r[k]===v);return q},ilike(k,v){rows=rows.filter(r=>r[k].toLowerCase().includes(v.slice(1,-1).toLowerCase()));return q},limit(){return q},maybeSingle(){return Promise.resolve({data:rows[0]??null,error:rows.length>1?{message:'multiple rows'}:errors[table]??null})},then(resolve){resolve({data:rows,error:errors[table]??null})}};return q;
  }};
}
const tables = {'labour_actuals_by_month':monthly,'labour_actuals_by_category':monthly,'labour_vintage_coverage':coverage};
async function summary(input, database=db(tables)) {
 const result=await runTool(database,'get_labour_summary',input,'real_only',new Map());
 assert.equal(result.isError,false); return {payload:JSON.parse(result.content.split('\n\n')[0]),text:result.content,database};
}
test('monthly totals select exact numeric text and honor month/vintage/category together',async()=>{
 const {payload,database}=await summary({vintage:2026,period_month:'2026-08'});
 assert.deepEqual(payload.totals.display,{labor_hours:'365.19',labor_cost:'20281.18',expense_cost:'5531.16',total_cost:'25812.34',cost_per_hour:'55.54'});
 assert.equal(payload.totals.expense_cost,'5531.16480000000038');
 assert(database.calls.some(c=>c[0]==='select'&&c[1].includes('expense_cost::text')));
 const filtered=await summary({vintage:2026,period_month:'2026-08-15',job_category:'irrig'});
 assert.equal(filtered.payload.categories.length,1);assert.equal(filtered.payload.totals.display.labor_cost,'2281.18');
 const other=await summary({vintage:2024,period_month:'2026-08'});assert.equal(other.payload.record_status,'no_records');
});
test('vintage totals and category scope keep expenses separate from weighted rate',async()=>{
 const {payload}=await summary({vintage:2026});
 assert.deepEqual(payload.totals.display,{labor_hours:'946.43',labor_cost:'49612.57',expense_cost:'9877.26',total_cost:'59489.83',cost_per_hour:'52.42'});
 const filtered=await summary({vintage:2026,job_category:'irrig'});assert.equal(filtered.payload.totals.display.labor_hours,'65.19');
});
test('empty month and empty vintage preserve distinct coverage in real-only mode',async()=>{
 const jan=await summary({vintage:2026,period_month:'2026-01'});
 assert.equal(jan.payload.record_status,'no_records');assert.equal(jan.payload.totals.cost_per_hour,null);
 assert.match(jan.text,/January 2026/);assert.match(jan.text,/July 2026 through August 2026 INCLUSIVE/);
 const june=await summary({vintage:2025,period_month:'2025-06'});assert.match(june.text,/No labour records exist for vintage 2025 at all/);
 const year=await summary({vintage:2025});assert.equal(year.payload.categories.length,0);
 const category=await summary({vintage:2026,job_category:'nonexistent'});assert.match(category.text,/job category filter/);
});
test('query and coverage errors are not evidence of absence',async()=>{
 for(const table of ['labour_actuals_by_month','labour_vintage_coverage']) {
 const result=await runTool(db(tables,{[table]:{message:'permission denied'}}),'get_labour_summary',{vintage:2026,period_month:'2026-01'});
 assert.equal(result.isError,true);
 }
});
test('zero hours, exact fractional cents, credits, weighted ratio and empty are explicit',()=>{
 const totals=rows=>JSON.parse(labourResult(rows,{})).totals;
 const r=(h,l,e)=>row(2026,'2026-08-01','test',h,l,e);
 assert.equal(totals([r('0','0','0.004'),r('0','0','0.004')]).display.expense_cost,'0.01');
 assert.equal(totals([r('0','1','100')]).cost_per_hour,null);
 assert.equal(totals([r('1','10','0'),r('3','90','500')]).cost_per_hour,'25.00');
 assert.equal(totals([r('0','-0.005','0')]).display.labor_cost,'-0.01');
 assert.equal(JSON.parse(labourResult([r('0','0','0')],{})).record_status,'records_present');
 assert.equal(JSON.parse(labourResult([],{})).record_status,'no_records');
});
test('admin with many visible profiles and operator each resolve only verified caller',async()=>{
 const users=[{id:'admin',first_name:'Admin',last_name:'Own'},{id:'operator',first_name:'Operator',last_name:'Own'}];
 for(const id of ['admin','operator']) {
 const database=db({user_profiles:users});const result=await callerProfile(database,{id});
 assert.equal(result.error,null);assert.equal(result.data.first_name,id==='admin'?'Admin':'Operator');
 assert(database.calls.some(c=>c[0]==='eq'&&c[1]==='id'&&c[2]===id));
 }
 const database=db({user_profiles:users});assert.equal((await callerProfile(database,null)).data,null);assert.equal(database.calls.length,0);
 assert.equal((await callerProfile(database,{id:'missing'})).data,null);
 for(const last of [null,'Name']) assert.equal(resolveDisplayName('operator',null,last),null);
 assert.equal(resolveDisplayName('operator','First',null),'First');assert.equal(resolveDisplayName('customer','First','Last'),'First Last');
});
