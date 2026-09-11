// Real browser regression using synthetic identities and intercepted APIs only.
// QA_DIST selects compiled assets. Never reuse a personal browser profile.
import { build } from 'esbuild'
import { readFile, mkdir } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import assert from 'node:assert/strict'

const playwright = await import(process.env.QA_PLAYWRIGHT_MODULE || 'playwright')
const engine = process.env.QA_BROWSER || 'chromium'
const browser = await playwright[engine].launch({ headless: true, ...(process.env.QA_BROWSER_EXECUTABLE ? {executablePath:process.env.QA_BROWSER_EXECUTABLE} : {}) })
const origin = 'https://app.wappie.thehappie.co', api = 'https://api.wappie.thehappie.co'
const dist = process.env.QA_DIST && resolve(process.env.QA_DIST)
const screenshots = process.env.QA_SCREENSHOTS
const team = '018f3a2b-2222-7000-8000-00000000bbbb', personal = '018f3a2b-2222-7000-8000-00000000cccc', deviceID = '018f3a2b-2222-7000-8000-00000000dddd'
const otherUser = '018f3a2b-2222-7000-8000-00000000aabb', inviteID = '018f3a2b-2222-7000-8000-00000000aacc'
const fixtureBundle = await build({ entryPoints:[fileURLToPath(new URL('./sessionFixture.ts',import.meta.url))], write:false, bundle:true, format:'esm', plugins:[{name:'test-locales',setup(b){b.onLoad({filter:/ui\/i18n.ts$/},async args=>({loader:'ts',contents:(await readFile(args.path,'utf8')).replace(/^const catalogs =.*$/m,'const catalogs = {}')}))}}] })
try {
  for (const mobile of [false, true]) {
    const context = await browser.newContext({ serviceWorkers:'block', locale:'pt-BR', colorScheme:'dark', viewport:mobile?{width:390,height:844}:{width:1360,height:900}, isMobile:mobile, hasTouch:mobile, reducedMotion:'reduce' })
    let fixture, signed=false, logins=0, workspace=team
    let profile={name:'Alex Morgan',email:'browser@example.test',avatar:''}
    let spaces=[{id:personal,name:'Alex Morgan',kind:'personal',role:'owner',status:'active',avatar:''},{id:team,name:'Acme Studio',kind:'team',role:'owner',status:'active',avatar:''}]
    let invitations=[{id:inviteID,email:'new@example.test',role:'member',status:'pending',created_at:new Date().toISOString(),expires_at:new Date(Date.now()+604800000).toISOString(),completed_at:null,revoked_at:null,can_reveal:true}]
    const errors=[], requests=[], commands=[]
    if (dist) await context.route('**/*',async route=>{
      const u=new URL(route.request().url())
      if(u.origin===origin && ['/','/console'].includes(u.pathname)) {
        const live=await route.fetch({url:origin+'/'})
        return route.fulfill({response:live,body:await readFile(resolve(dist,'index.html'))})
      }
      if([origin,api].includes(u.origin)&&u.pathname.startsWith('/assets/')) {
        try{return await route.fulfill({status:200,contentType:u.pathname.endsWith('.css')?'text/css':'application/javascript',body:await readFile(resolve(dist,'.'+u.pathname))})}catch{}
      }
      return route.fallback()
    })
    await context.route('**/qa-fixture.js',route=>route.fulfill({contentType:'application/javascript',body:fixtureBundle.outputFiles[0].text}))
    await context.route('**/v1/**',async route=>{
      const request=route.request(), path=new URL(request.url()).pathname, method=request.method()
      requests.push({path,method})
      const json=(value,status=200)=>route.fulfill({json:value,status})
      if(path==='/v1/auth/signup/config')return json({enabled:true,email_verification_required:true})
      if(path==='/v1/auth/passkeys/config')return json({enabled:false})
      if(path==='/v1/auth/passkeys')return json({passkeys:[]})
      if(path==='/v1/auth/challenge')return json(fixture.challenge)
      if(path==='/v1/auth/login'){logins++;signed=request.postDataJSON().auth_key===fixture.authKey;workspace=team;return json(signed?fixture.reply:{code:'bad_credentials'},signed?200:401)}
      if(path==='/v1/auth/me') {
        const selected=(request.headers().authorization||'').includes('personal')?personal:team
        return json(signed?{user:{...fixture.reply.user,...profile,tenant_id:selected},expires_at:fixture.reply.expires_at,grants:selected===team?fixture.grants:[]}:{code:'unauthorized'},signed?200:401)
      }
      if(path==='/v1/auth/workspaces/session'){workspace=request.postDataJSON().tenant_id;return json({...fixture.reply,token:workspace===personal?'synthetic-personal':'synthetic-team',user:{...fixture.reply.user,...profile,tenant_id:workspace}})}
      if(path==='/v1/auth/profile'){if(method==='PUT')profile={...profile,...request.postDataJSON()};return json({id:fixture.reply.user.id,...profile})}
      if(path==='/v1/auth/workspaces/current'){spaces=spaces.map(s=>s.id===workspace?{...s,...request.postDataJSON()}:s);return json(spaces.find(s=>s.id===workspace))}
      if(path==='/v1/auth/workspaces')return json({workspaces:spaces})
      if(path==='/v1/auth/workspaces/capacity')return json({max_devices:5,used_devices:workspace===team?1:0})
      if(path==='/v1/auth/workspaces/members')return json({members:[{id:fixture.reply.user.id,...profile,role:'owner',status:'active',last_owner:true,device_access:[{device_id:deviceID,label:'Support',pn:'15550001111@s.whatsapp.net',has_key:true,read:true,send:true,manage:true}]},{id:otherUser,email:'member@example.test',name:'Jamie Rivera',avatar:'',role:'member',status:'active',device_access:[]}]})
      if(path.endsWith('/permissions'))return json({permissions:[{device_id:deviceID,user_id:fixture.reply.user.id,read:true,send:true,manage:true,has_key:true},{device_id:deviceID,user_id:otherUser,read:false,send:false,manage:false,has_key:false}]})
      if(path==='/v1/auth/workspaces/invites')return json({invites:invitations})
      if(path.endsWith('/reveal'))return json({invite:'synthetic-shareable-invite'})
      if(path===`/v1/auth/workspaces/invites/${inviteID}`&&method==='DELETE'){invitations=invitations.map(i=>({...i,status:'revoked',revoked_at:new Date().toISOString()}));return route.fulfill({status:204})}
      if(path==='/v1/auth/logout')return route.fulfill({status:204})
      if(path==='/v1/auth/workspaces/accept-invite')return json({code:'invite_email_mismatch'},403)
      return json({code:'not_found'},404)
    })
    await context.routeWebSocket('**/v1/ws',socket=>socket.onMessage(raw=>{
      const f=JSON.parse(String(raw));commands.push(f.t)
      const send=(t,p)=>socket.send(JSON.stringify({t,r:f.r,p}))
      const device={id:deviceID,label:'Support',push_name:'Acme Support',pn:'15550001111@s.whatsapp.net',can_send:true,can_manage:true,status:'online',running:true,receipt_mode:'passive',reader_receipt_mode:'passive',created_at:new Date().toISOString()}
      switch(f.t){
        case 'hello':workspace=f.p.session?.includes('personal')?personal:team;return send('welcome',{version:1,tenant_id:workspace,account:fixture.email,role:'owner',features:[],server_ts:Date.now()})
        case 'devices.list':return send('devices',{devices:workspace===team?[device]:[]})
        case 'devices.stats':return send('devices.stats.result',{stats:[{device_id:deviceID,chats:12,messages:280,media:13,media_bytes:102400}]})
        case 'users.list':return send('users',{users:[{id:fixture.reply.user.id,email:fixture.email,role:'owner',public_key:fixture.reply.user.public_key}]})
        case 'apikeys.list':return send('apikeys',{keys:[]})
        case 'device.info':return send('device.detail',{device,stats:{device_id:deviceID,chats:12,messages:280,media:13,media_bytes:102400},readers:[{user_id:fixture.reply.user.id,email:fixture.email,role:'owner',epoch:1,granted_at:new Date().toISOString()}],epoch:1})
        case 'chats.list':return send('chats',{device_id:deviceID,chats:[]})
        case 'contacts.list':return send('contacts',{device_id:deviceID,contacts:[]})
        default:return send('error',{code:'not_found',message:'Synthetic resource unavailable'})
      }
    }))
    const page=await context.newPage()
    page.on('pageerror',e=>errors.push(e.message))
    page.on('console',m=>{if(m.type()==='error'&&/Content Security Policy|Refused to|TypeError/.test(m.text()))errors.push(m.text())})
    await page.goto(origin+'/console')
    await page.locator('input[name=username]').waitFor()
    await page.addScriptTag({type:'module',url:origin+'/qa-fixture.js'})
    await page.waitForFunction(()=>typeof window.prepareLoginFixture==='function')
    fixture=await page.evaluate(()=>window.prepareLoginFixture())
    await page.locator('input[name=username]').fill(fixture.email)
    await page.locator('input[name=password]').fill(fixture.password)
    await page.locator('form[name=wappie-login] button[type=submit]').click()
    await page.locator('.console-main').waitFor()
    const nav=async label=>{if(mobile)await page.getByRole('button',{name:'Abrir menu',exact:true}).click();await page.locator('.console-nav:visible').getByRole('button',{name:new RegExp('^'+label+'(?:$|[0-9 ])')}).click()}
    const switcher=async()=>{if(mobile)await page.getByRole('button',{name:'Abrir menu',exact:true}).click();await page.locator('.workspace-trigger:visible').click()}
    const closeTop=()=>page.locator('dialog[open]').last().getByRole('button',{name:'Fechar',exact:true}).click()
    assert.equal(await page.locator('.console-nav-item').filter({hasText:/^Permissões$|^Espaço de trabalho$/}).count(),0)
    await switcher()
    assert.match(await page.locator('.workspace-trigger:visible').innerText(),/Team[\s\S]*Proprietário/)
    assert.equal(await page.locator('.space-choice').count(),2)
    assert.match(await page.locator('.workspace-popup').innerText(),/Pessoal/)
    assert.match(await page.locator('.workspace-popup').innerText(),/Proprietário/)
    if(screenshots&&engine==='chromium'){await mkdir(screenshots,{recursive:true});await page.screenshot({path:resolve(screenshots,`workspace-${mobile?'mobile':'desktop'}.png`)})}
    await page.getByRole('button',{name:'Criar workspace Team',exact:true}).click()
    await page.getByRole('textbox',{name:'Nome do workspace'}).fill('New team')
    await page.getByRole('button',{name:'Cancelar',exact:true}).click()
    if(mobile)await closeTop()
    await nav('Membros')
    await page.getByText('Jamie Rivera',{exact:true}).waitFor()
    await page.getByText('new@example.test',{exact:true}).waitFor()
    assert.match(await page.locator('.members-panel').innerText(),/Support/)
    await page.getByRole('button',{name:'Ver convite',exact:true}).click()
    await page.getByRole('heading',{name:'Convite do workspace',exact:true}).waitFor(); assert.equal(await page.getByRole('textbox',{name:'Código de convite'}).inputValue(),'synthetic-shareable-invite')
    await closeTop()
    if(mobile)await page.getByRole('button',{name:'Minha conta',exact:true}).filter({visible:true}).click();else await page.locator('.profile-trigger:visible').click()
    await page.locator('.account-settings:visible').waitFor()
    await page.locator('.security-summary').filter({hasText:'Trocar sua senha de acesso'}).click()
    assert.equal(await page.locator('form[name=wappie-password-change] input[type=password]').count(),3)
    await closeTop()
    await page.locator('.security-summary').filter({hasText:'Passkeys'}).click()
    await page.getByRole('dialog',{name:'Passkeys',exact:true}).waitFor()
    await closeTop()
    if(screenshots&&engine==='chromium')await page.screenshot({path:resolve(screenshots,`account-${mobile?'mobile':'desktop'}.png`)})
    await nav('Números')
    await page.getByRole('button',{name:'Detalhes',exact:true}).click()
    await page.getByRole('heading',{name:'Membros e permissões',exact:true}).waitFor()
    await page.getByRole('checkbox',{name:'Permitir leitura para Jamie Rivera',exact:true}).waitFor({state:'visible'})
    assert.equal(await page.getByText('Confirmar leitura no WhatsApp (sai do modo discreto)',{exact:true}).count(),0)
    await page.keyboard.press('Escape')
    await page.reload();await page.locator('.console-main').waitFor()
    assert.equal(logins,1,'reload retains session')
    let releaseNavigation, navigationRequested
    const navigationGate=new Promise(resolve=>{releaseNavigation=resolve})
    const navigationSeen=new Promise(resolve=>{navigationRequested=resolve})
    await context.route(origin+'/console?workspace='+personal,async route=>{navigationRequested();await navigationGate;await route.fallback()})
    await switcher()
    let recordTransition
    const transitionSeen=new Promise(resolve=>{recordTransition=resolve})
    await page.exposeFunction('recordWorkspaceTransition',snapshot=>recordTransition(snapshot))
    await page.evaluate(()=>{
      const observer=new MutationObserver(()=>{
        const loading=!!document.querySelector('.app-loading'), login=!!document.querySelector('form[name=wappie-login]')
        if(loading||login){observer.disconnect();void window.recordWorkspaceTransition({loading,login})}
      })
      observer.observe(document.body,{childList:true,subtree:true})
    })
    const changing=page.locator('.space-choice').filter({hasText:'Pessoal'}).click({noWaitAfter:true})
    await navigationSeen
    let timeout
    try {
      const observed=await Promise.race([transitionSeen,new Promise((_,reject)=>{timeout=setTimeout(()=>reject(new Error('Workspace loading screen was not rendered')),5000)})])
      assert.deepEqual(observed,{loading:true,login:false},'workspace navigation must never flash login')
    } finally { clearTimeout(timeout);releaseNavigation() }
    await changing
    await page.waitForURL('**workspace='+personal);await page.locator('.console-main').waitFor()
    assert.equal(logins,1,'workspace switch retains session')
    await page.getByText('Conecte seu primeiro número',{exact:true}).waitFor()
    await page.goto(origin+'/console#invite=wrong-recipient-code&email=another%40example.test')
    await page.getByRole('heading',{name:'Entrar em um workspace',exact:true}).waitFor()
    assert.equal(page.url().includes('wrong-recipient-code'),false)
    assert.equal(await page.getByRole('button',{name:'Aceitar convite',exact:true}).isDisabled(),true,'a known recipient mismatch cannot be submitted'); await closeTop(); await page.goto(origin+'/console#invite=wrong-recipient-code'); await page.getByRole('heading',{name:'Entrar em um workspace',exact:true}).waitFor(); await page.getByRole('button',{name:'Aceitar convite',exact:true}).click()
    await page.getByText(/Este convite pertence a outro email/).waitFor()
    assert.equal(await page.getByRole('textbox',{name:'Código de convite'}).inputValue(),'wrong-recipient-code')
    assert.equal(logins,1)
    await closeTop()
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'no horizontal overflow'); await page.goto(origin+'/console?signup=1#email=new%40example.test&verification=synthetic-proof'); await page.locator('#display-name').waitFor(); assert.equal(await page.locator('#email').inputValue(),'new@example.test'); assert.equal(await page.locator('#email-verification').inputValue(),'synthetic-proof'); assert.equal(await page.locator('#invite').getAttribute('required'),null); assert.equal(page.url().includes('synthetic-proof'),false); await page.emulateMedia({colorScheme:'light'}); if(screenshots&&engine==='chromium')await page.screenshot({path:resolve(screenshots,`signup-light-${mobile?'mobile':'desktop'}.png`)})
    // Known Playwright WebKit screenshot preparation inserts inline styles;
    // screenshots above are Chrome-only to keep this CSP check meaningful.
    assert.deepEqual(errors,[])
    console.log(JSON.stringify({engine,mobile,logins,apiRequests:requests.length,checks:'workspace/menu/members/invites/security/permissions/restoration',errors}))
    await context.close()
  }
}catch(error){console.error('Console browser verification failed:',error);throw error}
finally{for(const context of browser.contexts())await context.unrouteAll({behavior:'ignoreErrors'});await browser.close()}
