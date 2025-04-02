const puppeteer = require('puppeteer-core');

const TIMEOUT = 30000;
const HOSTNAME = process.env.HOSTNAME ?? 'http://localhost:3000';
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function browse(url){
    let browser;
    try{
        console.log(`Opening browser for ${url}`);
        browser = await puppeteer.launch({
            headless: true,
            pipe: true,
            executablePath: '/usr/bin/chromium',
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-gpu',
                '--jitless'
            ]
        });
        const ctx = await browser.createBrowserContext();
        await Promise.race([
            sleep(TIMEOUT),
            visit(ctx, url),
        ]);
    }catch(e){
        console.error('Failed to browse:', e);
    }finally{
        if(browser){
            try{
                await browser.close();
            }catch(e){
                console.error('Failed to close browser:', e);
            }
        }
    }
}

async function visit(ctx, url){
    page = await ctx.newPage();
    console.log('Visting ', url);
    await page.goto(url);
    await sleep(TIMEOUT);
    await page.close();
}

module.exports = {browse};