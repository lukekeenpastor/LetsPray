# Sections and sign-in (Students, Kids, Board, Staff)

This branch turns Let's Pray into one app with four sections. Each section has its own roster, its own weekly history, and its own list of leaders who may open it. Leaders sign in with their email address (a one-time code is emailed to them). They need no Claude, GitHub or Cloudflare account.

**Do not merge this until the Cloudflare steps below are done.** Until then the site shows "Almost ready" and stays closed, on purpose.

## What changed

- Every API call now checks a signed Cloudflare Access login on the server. Nothing is trusted from the browser.
- The old admin password is gone. Admins are the emails in `ADMIN_EMAILS`.
- Admins add leaders to each section from the app: footer link **manage access**.
- Students and Kids are shown as **First name + last initial**. The server enforces this when saving and when sending data, and the app does the same on screen.
- Kids, Board and Staff keep names only: no birthdays, grades or prayer requests are stored there.
- Students keeps birthdays, grades and prayer requests as before.
- Existing Students data is untouched and keeps working.
- Leaders can mark people prayed for. Only admins can force-overwrite a roster, change the ministry name, or edit access lists.

## One-time Cloudflare setup (about 15 minutes)

1. **Zero Trust:** In the Cloudflare dashboard open **Zero Trust**. If asked, pick a team name (for example `quincyfaith`) and the Free plan. Your team domain is `quincyfaith.cloudflareaccess.com`.
2. **Add the application:** Zero Trust → **Access → Applications → Add an application → Self-hosted**.
   - Application domains: your Pages address, and the same with a wildcard so preview addresses are covered too, for example `letspray2.pages.dev` and `*.letspray2.pages.dev`. Add your own domain too if you have one.
   - Login method: **One-time PIN**.
   - Policy: **Allow**, include **Everyone**. (The app itself decides who may open which section, so you only manage one list.)
3. **Copy the Application Audience (AUD) tag** from the application's overview page.
4. **Add three variables:** Workers & Pages → your project → **Settings → Variables and Secrets**, for both Production and Preview:
   - `ACCESS_TEAM_DOMAIN` = `quincyfaith.cloudflareaccess.com`
   - `ACCESS_AUD` = the AUD tag from step 3
   - `ADMIN_EMAILS` = your email, and any other admins, separated by commas
5. **Merge this branch.** Cloudflare redeploys in a minute or two.
6. **Test in a private browser window**, on every address the site has (the main one and any preview one). Each should ask for an email, send a code, and then open the app. An address that opens the app without asking for an email means step 2 missed it.
7. Open the app, choose **manage access**, and add each leader's email under the sections they should see.

## Things to know

- **Last names are removed for good.** The first time anyone saves the Students roster after this goes live, the stored full names are replaced with first name + last initial. Keep a copy elsewhere (Planning Center is the source) if you want the full names.
- **"Everyone" in the Cloudflare policy** only proves someone owns an email address. A person who is not on a section list sees "You don't have access yet" and nothing else. If you would rather keep strangers from even receiving a code, add your leaders' emails to the Access policy as well. Free plans cover up to 50 people in total.
- **Tests:** `node server/access.test.mjs` runs the server checks (forged, expired and tampered logins, section separation, name rules).
