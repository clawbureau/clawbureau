> **Type:** Reference
> **Status:** REFERENCE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** Cloudflare blog / moltworker project (copied reference)
>
> **Scope:**
> - Reference material about running an agent on Cloudflare (Sandbox SDK + Workers).
> - Not a Claw Bureau spec; used as background for `clawea`/runner discussions.

# Cloudflare moltworker reference

2026-01-29

9 min read

![](https://cf-assets.www.cloudflare.com/zkvhlag99gkb/7ogFfJCoxbBXYOCrHG8xSF/5790f31aa4cb8222ef227b2a762a2ebc/image2.png)

*Editorial note: As of January 30, 2026, Moltbot has been* [*renamed*](https://openclaw.ai/blog/introducing-openclaw) *to OpenClaw.*

The Internet woke up this week to a flood of people [buying Mac minis](https://x.com/AlexFinn/status/2015133627043270750) to run [Moltbot](https://github.com/moltbot/moltbot) (formerly Clawdbot), an open-source, self-hosted AI agent designed to act as a personal assistant. Moltbot runs in the background on a user's own hardware, has a sizable and growing list of integrations for chat applications, AI models, and other popular tools, and can be controlled remotely. Moltbot can help you with your finances, social media, organize your day — all through your favorite messaging app.

But what if you don’t want to buy new dedicated hardware? And what if you could still run your Moltbot efficiently and securely online? Meet [Moltworker](https://github.com/cloudflare/moltworker), a middleware Worker and adapted scripts that allows running Moltbot on Cloudflare's Sandbox SDK and our Developer Platform APIs.

## A personal assistant on Cloudflare — how does that work?

Cloudflare Workers has never been [as compatible](https://developers.cloudflare.com/workers/runtime-apis/nodejs/) with Node.js as it is now. Where in the past we had to mock APIs to get some packages running, now those APIs are supported natively by the Workers Runtime.

This has changed how we can build tools on Cloudflare Workers. When we first implemented [Playwright](https://developers.cloudflare.com/browser-rendering/playwright/), a popular framework for web testing and automation that runs on [Browser Rendering](https://developers.cloudflare.com/browser-rendering/), we had to rely on [memfs](https://www.npmjs.com/package/memfs). This was bad because not only is memfs a hack and an external dependency, but it also forced us to drift away from the official Playwright codebase. Thankfully, with more Node.js compatibility, we were able to start using [node:fs natively](https://github.com/cloudflare/playwright/pull/62/changes), reducing complexity and maintainability, which makes upgrades to the latest versions of Playwright easy to do.

The list of Node.js APIs we support natively keeps growing. The blog post “ [A year of improving Node.js compatibility in Cloudflare Workers](https://blog.cloudflare.com/nodejs-workers-2025/) ” provides an overview of where we are and what we’re doing.

We measure this progress, too. We recently ran an experiment where we took the 1,000 most popular NPM packages, installed and let AI loose, to try to run them in Cloudflare Workers, [Ralph Wiggum as a "software engineer"](https://ghuntley.com/ralph/) style, and the results were surprisingly good. Excluding the packages that are build tools, CLI tools or browser-only and don’t apply, only 15 packages genuinely didn’t work. **That's 1.5%**.

Here’s a graphic of our Node.js API support over time:

![](https://cf-assets.www.cloudflare.com/zkvhlag99gkb/5GhwKJq2A2wG79I3NdhhDl/e462c30daf46b1b36d3f06bff479596b/image9.png)

We put together a page with the results of our internal experiment on npm packages support [here](https://worksonworkers.southpolesteve.workers.dev/), so you can check for yourself.

Moltbot doesn’t necessarily require a lot of Workers Node.js compatibility because most of the code runs in a container anyway, but we thought it would be important to highlight how far we got supporting so many packages using native APIs. This is because when starting a new AI agent application from scratch, we can actually run a lot of the logic in Workers, closer to the user.

The other important part of the story is that the list of [products and APIs](https://developers.cloudflare.com/directory/?product-group=Developer+platform) on our Developer Platform has grown to the point where anyone can build and run any kind of application — even the most complex and demanding ones — on Cloudflare. And once launched, every application running on our Developer Platform immediately benefits from our secure and scalable global network.

Those products and services gave us the ingredients we needed to get started. First, we now have [Sandboxes](https://sandbox.cloudflare.com/), where you can run untrusted code securely in isolated environments, providing a place to run the service. Next, we now have [Browser Rendering](https://developers.cloudflare.com/browser-rendering/), where you can programmatically control and interact with headless browser instances. And finally, [R2](https://developers.cloudflare.com/r2/), where you can store objects persistently. With those building blocks available, we could begin work on adapting Moltbot.

## How we adapted Moltbot to run on us

Moltbot on Workers, or Moltworker, is a combination of an entrypoint Worker that acts as an API router and a proxy between our APIs and the isolated environment, both protected by Cloudflare Access. It also provides an administration UI and connects to the Sandbox container where the standard Moltbot Gateway runtime and its integrations are running, using R2 for persistent storage.

![](https://cf-assets.www.cloudflare.com/zkvhlag99gkb/3OD2oHgy5ilHpQO2GJvcLU/836a55b67a626d2cd378a654ad47901d/newdiagram.png)

<sup>High-level architecture diagram of Moltworker.</sup>

Let's dive in more.

### AI Gateway

Cloudflare AI Gateway acts as a proxy between your AI applications and any popular [AI provider](https://developers.cloudflare.com/ai-gateway/usage/providers/), and gives our customers centralized visibility and control over the requests going through.

Recently we announced support for [Bring Your Own Key (BYOK)](https://developers.cloudflare.com/changelog/2025-08-25-secrets-store-ai-gateway/), where instead of passing your provider secrets in plain text with every request, we centrally manage the secrets for you and can use them with your gateway configuration.

An even better option where you don’t have to manage AI providers' secrets at all end-to-end is to use [Unified Billing](https://developers.cloudflare.com/ai-gateway/features/unified-billing/). In this case you top up your account with credits and use AI Gateway with any of the supported providers directly, Cloudflare gets charged, and we will deduct credits from your account.

To make Moltbot use AI Gateway, first we create a new gateway instance, then we enable the Anthropic provider for it, then we either add our Claude key or purchase credits to use Unified Billing, and then all we need to do is set the ANTHROPIC\_BASE\_URL environment variable so Moltbot uses the AI Gateway endpoint. That’s it, no code changes necessary.

![](https://cf-assets.www.cloudflare.com/zkvhlag99gkb/cMWRXgHR0mFLc5kp74nYk/a47fa09bdbb6acb3deb60fb16537945d/image11.png)

Once Moltbot starts using AI Gateway, you’ll have full visibility on costs and have access to logs and analytics that will help you understand how your AI agent is using the AI providers.

![](https://cf-assets.www.cloudflare.com/zkvhlag99gkb/5GOrNdgtdwMcU4bE8oLE19/6bc29bcac643125f5332a8ffba9d1322/image1.png)

Note that Anthropic is one option; Moltbot supports [other](https://www.molt.bot/integrations) AI providers and so does [AI Gateway](https://developers.cloudflare.com/ai-gateway/usage/providers/). The advantage of using AI Gateway is that if a better model comes along from any provider, you don’t have to swap keys in your AI Agent configuration and redeploy — you can simply switch the model in your gateway configuration. And more, you specify model or provider [fallbacks](https://developers.cloudflare.com/ai-gateway/configuration/fallbacks/) to handle request failures and ensure reliability.

### Sandboxes

Last year we anticipated the growing need for AI agents to run untrusted code securely in isolated environments, and we [announced](https://developers.cloudflare.com/changelog/2025-06-24-announcing-sandboxes/) the [Sandbox SDK](https://developers.cloudflare.com/sandbox/). This SDK is built on top of [Cloudflare Containers](https://developers.cloudflare.com/containers/), but it provides a simple API for executing commands, managing files, running background processes, and exposing services — all from your Workers applications.

In short, instead of having to deal with the lower-level Container APIs, the Sandbox SDK gives you developer-friendly APIs for secure code execution and handles the complexity of container lifecycle, networking, file systems, and process management — letting you focus on building your application logic with just a few lines of TypeScript. Here’s an example:

```typescript
import { getSandbox } from '@cloudflare/sandbox';
export { Sandbox } from '@cloudflare/sandbox';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const sandbox = getSandbox(env.Sandbox, 'user-123');

    // Create a project structure
    await sandbox.mkdir('/workspace/project/src', { recursive: true });

    // Check node version
    const version = await sandbox.exec('node -v');

    // Run some python code
    const ctx = await sandbox.createCodeContext({ language: 'python' });
    await sandbox.runCode('import math; radius = 5', { context: ctx });
    const result = await sandbox.runCode('math.pi * radius ** 2', { context: ctx });

    return Response.json({ version, result });
  }
};
```

This fits like a glove for Moltbot. Instead of running Docker in your local Mac mini, we run Docker on Containers, use the Sandbox SDK to issue commands into the isolated environment and use callbacks to our entrypoint Worker, effectively establishing a two-way communication channel between the two systems.

### R2 for persistent storage

The good thing about running things in your local computer or VPS is you get persistent storage for free. Containers, however, are inherently [ephemeral](https://developers.cloudflare.com/containers/platform-details/architecture/), meaning data generated within them is lost upon deletion. Fear not, though — the Sandbox SDK provides the sandbox.mountBucket() that you can use to automatically, well, mount your R2 bucket as a filesystem partition when the container starts.

Once we have a local directory that is guaranteed to survive the container lifecycle, we can use that for Moltbot to store session memory files, conversations and other assets that are required to persist.

### Browser Rendering for browser automation

AI agents rely heavily on browsing the sometimes not-so-structured web. Moltbot utilizes dedicated Chromium instances to perform actions, navigate the web, fill out forms, take snapshots, and handle tasks that require a web browser. Sure, we can run Chromium on Sandboxes too, but what if we could simplify and use an API instead?

With Cloudflare’s [Browser Rendering](https://developers.cloudflare.com/browser-rendering/), you can programmatically control and interact with headless browser instances running at scale in our edge network. We support [Puppeteer](https://developers.cloudflare.com/browser-rendering/puppeteer/), [Stagehand](https://developers.cloudflare.com/browser-rendering/stagehand/), [Playwright](https://developers.cloudflare.com/browser-rendering/playwright/) and other popular packages so that developers can onboard with minimal code changes. We even support [MCP](https://developers.cloudflare.com/browser-rendering/playwright/playwright-mcp/) for AI.

In order to get Browser Rendering to work with Moltbot we do two things:

- First we create a [thin CDP proxy](https://github.com/cloudflare/moltworker/blob/main/src/routes/cdp.ts) ([CDP](https://chromedevtools.github.io/devtools-protocol/) is the protocol that allows instrumenting Chromium-based browsers) from the Sandbox container to the Moltbot Worker, back to Browser Rendering using the Puppeteer APIs.
- Then we inject a [Browser Rendering skill](https://github.com/cloudflare/moltworker/pull/20) into the runtime when the Sandbox starts.
![](https://cf-assets.www.cloudflare.com/zkvhlag99gkb/1ZvQa7vS1T9Mm3nywqarQZ/9dec3d8d06870ee575a519440d34c499/image12.png)

From the Moltbot runtime perspective, it has a local CDP port it can connect to and perform browser tasks.

### Zero Trust Access for authentication policies

Next up we want to protect our APIs and Admin UI from unauthorized access. Doing authentication from scratch is hard, and is typically the kind of wheel you don’t want to reinvent or have to deal with. Zero Trust Access makes it incredibly easy to protect your application by defining specific policies and login methods for the endpoints.

![](https://cf-assets.www.cloudflare.com/zkvhlag99gkb/1MDXXjbMs4PViN3kp9iFBY/a3095f07c986594d0c07d0276dbf22cc/image3.png)

<sup>Zero Trust Access Login methods configuration for the Moltworker application.</sup>

Once the endpoints are protected, Cloudflare will handle authentication for you and automatically include a with every request to your origin endpoints. You can then that JWT for extra protection, to ensure that the request came from Access and not a malicious third party.

Like with AI Gateway, once all your APIs are behind Access you get great observability on who the users are and what they are doing with your Moltbot instance.

![](https://cf-assets.www.cloudflare.com/zkvhlag99gkb/3BV4eqxKPXTiq18vvVpmZh/e034b7e7ea637a00c73c2ebe4d1400aa/image8.png)

## Moltworker in action

Demo time. We’ve put up a Slack instance where we could play with our own instance of Moltbot on Workers. Here are some of the fun things we’ve done with it.

We hate bad news.

![](https://cf-assets.www.cloudflare.com/zkvhlag99gkb/4FxN935AgINZ8953WSswKB/e52d3eb268aa0732c5e6aa64a8e2adba/image6.png)

Here’s a chat session where we ask Moltbot to find the shortest route between Cloudflare in London and Cloudflare in Lisbon using Google Maps and take a screenshot in a Slack channel. It goes through a sequence of steps using Browser Rendering to navigate Google Maps and does a pretty good job at it. Also look at Moltbot’s memory in action when we ask him the second time.

![](https://cf-assets.www.cloudflare.com/zkvhlag99gkb/1phWt3cVUwxe9tvCYpuAW3/97f456094ede6ca8fb55bf0dddf65d5b/image10.png)

We’re in the mood for some Asian food today, let’s get Moltbot to work for help.

![](https://cf-assets.www.cloudflare.com/zkvhlag99gkb/6nJY7GOCopGnMy4IY7KMcf/0d57794df524780c3f4b27e65c968e19/image5.png)

We eat with our eyes too.

![](https://cf-assets.www.cloudflare.com/zkvhlag99gkb/5BzB9pqJhuevRbOSJloeG0/23c2905f0c12c1e7f104aa28fcc1f595/image7.png)

Let’s get more creative and ask Moltbot to create a video where it browses our developer documentation. As you can see, it downloads and runs ffmpeg to generate the video out of the frames it captured in the browser.

## Run your own Moltworker

We open-sourced our implementation and made it available at [https://github.com/cloudflare/moltworker](https://github.com/cloudflare/moltworker), so you can deploy and run your own Moltbot on top of Workers today.

The [README](https://github.com/cloudflare/moltworker/blob/main/README.md) guides you through the necessary steps to set up everything. You will need a Cloudflare account and a minimum $5 USD [Workers paid plan](https://developers.cloudflare.com/workers/platform/pricing/) subscription to use Sandbox Containers, but all the other products are either free to use, like [AI Gateway](https://developers.cloudflare.com/ai-gateway/reference/pricing/), or have generous [free tiers](https://developers.cloudflare.com/r2/pricing/#free-tier) you can use to get you started and run for as long as you want under reasonable limits.

**Note that Moltworker is a proof of concept, not a Cloudflare product**. Our goal is to showcase some of the most exciting features of our [Developer Platform](https://developers.cloudflare.com/learning-paths/workers/devplat/intro-to-devplat/) that can be used to run AI agents and unsupervised code efficiently and securely, and get great observability while taking advantage of our global network.

Feel free to contribute to or fork our [GitHub](https://github.com/cloudflare/moltworker) repository; we will keep an eye on it for a while for support. We are also considering contributing upstream to the official project with Cloudflare skills in parallel.

## Conclusion

We hope you enjoyed this experiment, and we were able to convince you that Cloudflare is the perfect place to run your AI applications and agents. We’ve been working relentlessly trying to anticipate the future and release features like the [Agents SDK](https://developers.cloudflare.com/agents/) that you can use to build your first agent [in minutes](https://developers.cloudflare.com/agents/guides/slack-agent/), [Sandboxes](https://developers.cloudflare.com/sandbox/) where you can run arbitrary code in an isolated environment without the complications of the lifecycle of a container, and [AI Search](https://developers.cloudflare.com/ai-search/), Cloudflare’s managed vector-based search service, to name a few.

Cloudflare now offers a complete toolkit for AI development: inference, storage APIs, databases, durable execution for stateful workflows, and built-in AI capabilities. Together, these building blocks make it possible to build and run even the most demanding AI applications on our global edge network.

If you're excited about AI and want to help us build the next generation of products and APIs, we're [hiring](https://www.cloudflare.com/en-gb/careers/jobs/?department=Engineering).

Cloudflare's connectivity cloud protects [entire corporate networks](https://www.cloudflare.com/network-services/), helps customers build [Internet-scale applications efficiently](https://workers.cloudflare.com/), accelerates any [website or Internet application](https://www.cloudflare.com/performance/accelerate-internet-applications/), [wards off DDoS attacks](https://www.cloudflare.com/ddos/), keeps [hackers at bay](https://www.cloudflare.com/application-security/), and can help you on [your journey to Zero Trust](https://www.cloudflare.com/products/zero-trust/).  
  
Visit [1.1.1.1](https://one.one.one.one/) from any device to get started with our free app that makes your Internet faster and safer.  