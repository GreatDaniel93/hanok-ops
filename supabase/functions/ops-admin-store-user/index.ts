import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.57.4";

const corsHeaders={
  "Access-Control-Allow-Origin":"*",
  "Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods":"POST, OPTIONS"
};
const json=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{...corsHeaders,"Content-Type":"application/json"}});

Deno.serve(async(req:Request)=>{
  if(req.method==="OPTIONS") return new Response("ok",{headers:corsHeaders});
  if(req.method!=="POST") return json({error:"Method not allowed"},405);
  const authHeader=req.headers.get("Authorization");
  if(!authHeader) return json({error:"Unauthorized"},401);

  const url=Deno.env.get("SUPABASE_URL")!;
  const anonKey=Deno.env.get("SUPABASE_ANON_KEY")!;
  const serviceKey=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const caller=createClient(url,anonKey,{global:{headers:{Authorization:authHeader}},auth:{persistSession:false,autoRefreshToken:false}});
  const admin=createClient(url,serviceKey,{auth:{persistSession:false,autoRefreshToken:false}});

  const {data:userData,error:userError}=await caller.auth.getUser();
  if(userError||!userData.user) return json({error:"Unauthorized"},401);

  const {data:profile,error:profileError}=await admin.from("ops_profiles").select("role").eq("user_id",userData.user.id).maybeSingle();
  if(profileError) return json({error:profileError.message},500);
  if(profile?.role!=="admin") return json({error:"Admin only"},403);

  let payload:any;
  try{payload=await req.json()}catch{return json({error:"Invalid JSON"},400)}
  const storeCode=String(payload.storeCode||"").toUpperCase().trim();
  const password=String(payload.password||"");
  if(!/^[A-Z0-9]{2,8}$/.test(storeCode)) return json({error:"Invalid store code"},400);
  if(password.length<8) return json({error:"Password must be at least 8 characters"},400);

  const {data:store,error:storeError}=await admin.from("ops_stores").select("id,code,name").eq("code",storeCode).eq("active",true).single();
  if(storeError||!store) return json({error:"Store not found"},404);

  const internalEmail=`store.${store.code.toLowerCase()}@hanokops.invalid`;
  const {data:listed,error:listError}=await admin.auth.admin.listUsers({page:1,perPage:1000});
  if(listError) return json({error:listError.message},500);
  let authUser=listed.users.find(u=>(u.email||"").toLowerCase()===internalEmail);

  if(!authUser){
    const {data,error}=await admin.auth.admin.createUser({email:internalEmail,password,email_confirm:true,user_metadata:{display_name:store.name,store_code:store.code}});
    if(error||!data.user) return json({error:error?.message||"Could not create account"},500);
    authUser=data.user;
  }else{
    const {data,error}=await admin.auth.admin.updateUserById(authUser.id,{password,email_confirm:true,user_metadata:{display_name:store.name,store_code:store.code}});
    if(error||!data.user) return json({error:error?.message||"Could not update account"},500);
    authUser=data.user;
  }

  const {error:upsertError}=await admin.from("ops_profiles").upsert({
    user_id:authUser.id,email:internalEmail,display_name:store.name,role:"store",store_id:store.id,updated_at:new Date().toISOString()
  },{onConflict:"user_id"});
  if(upsertError) return json({error:upsertError.message},500);

  return json({ok:true,username:store.name,storeCode:store.code});
});