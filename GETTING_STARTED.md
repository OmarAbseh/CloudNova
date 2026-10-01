# Getting Started with CloudNova

A friendly, plain-language walkthrough. No prior experience needed - copy, paste,
and go. CloudNova has two sides:

- **The scanner** - finds security problems in cloud setups (Terraform, AWS, etc.).
- **Range** - your authorized pentest toolkit *and* a tutor that teaches you to hack, legally.

---

## 1. Install it (2 minutes)

You need Python 3.11 or newer. Then:

```bash
git clone https://github.com/OmarAbseh/CloudNova.git
cd CloudNova
pip install -e .            # the core tool

# optional add-ons:
pip install -e ".[web]"     # the browser dashboard
pip install -e ".[agent]"   # the Claude-powered mentor Q&A
```

Check it worked:

```bash
cloudnova --help
```

---

## 2. Scan something (the core feature)

Point it at a folder of cloud config files:

```bash
cloudnova scan examples          # scan the bundled examples
cloudnova scan ./my-infra        # scan your own Terraform/CloudFormation/K8s
```

You'll get a table of findings, a **posture grade (A-F)**, and any **attack paths**
(chains like "internet-exposed server → admin role → your database").

Useful options:

```bash
cloudnova scan . --min-severity high     # only show serious stuff
cloudnova scan . --format html > report.html   # a shareable report you open in a browser
cloudnova scan . --fail-on high          # for CI: exits with an error if it finds high+ issues
```

---

## 3. See it in a browser (the website)

```bash
pip install -e ".[web]"
cloudnova-web
```

Open **http://127.0.0.1:8000** - run scans and read results in a friendly UI, and
browse the learning path. It only runs on your own machine.

---

## 4. Work with IAM (AWS permissions)

**Write** a safe, least-privilege policy from plain intentions:

```bash
cloudnova iam generate examples/iam/app-grants.yaml -o policy.json
```

**Check** any policy for dangerous mistakes:

```bash
cloudnova iam analyze policy.json    # flags wildcards, privilege-escalation, etc.
```

---

## 5. Range - your pentest toolkit + tutor

Everything in Range is **authorization-first**: it will only work on targets you've
declared you're allowed to test. That's what keeps it legal.

### a) Say what you're allowed to test

Copy `examples/range/scope.example.yaml`, edit it to list your authorized targets
(your own lab, a practice box, or a bug-bounty program's in-scope assets), then:

```bash
cloudnova range scope my-scope.yaml               # show what's authorized
cloudnova range check api.example.com -s my-scope.yaml   # ALLOW or DENY?
```

### b) Learn to hack (the mentor)

```bash
cloudnova range mentor path                # your full learning path, in order
cloudnova range mentor topic burp-suite    # learn a tool/topic
cloudnova range mentor cert OSCP           # a certification prep track
cloudnova range mentor jobs junior         # what a junior pentest job expects
cloudnova range mentor ask "how do I test for XSS with Burp?"   # ask anything
cloudnova range mentor lab box.example.com -s my-scope.yaml     # guided practice session
```

> Tip: set `ANTHROPIC_API_KEY` and `pip install -e ".[agent]"` so `mentor ask`
> answers with the full Claude-powered tutor. Without a key it still gives useful
> curriculum answers.

### c) Organize recon + write the report

```bash
# You run nmap on your authorized target, then:
cloudnova range recon nmap-output.xml -s my-scope.yaml    # tidy inventory, scope-checked

# Turn your findings into a professional report:
cloudnova range report examples/range/engagement.example.yaml -o report.md
```

### d) Make it yours

```bash
cloudnova range whoami                 # who am I set up as?
cloudnova range persona use gh0st      # switch to your personal handle
```

---

## 6. Let an AI agent drive it (MCP)

```bash
pip install -e ".[mcp]"
cloudnova-mcp        # exposes scan / list_checks / attack_paths to Claude or any MCP client
```

---

## The golden rules (read once)

1. **Only test what you're authorized to test.** Your own lab, practice platforms
   (TryHackMe, HackTheBox, OWASP Juice Shop), or a bug-bounty program's published
   scope. Range enforces this, but *you* are responsible.
2. **Learn by doing on practice targets first.** The mentor is there to make you
   genuinely good - that's what lands the job and the bounty.
3. **Never submit findings you don't understand.** Validate first; the mentor
   teaches you how.

---

## Where to go next

- `README.md` - the overview and architecture.
- `ROADMAP.md` - what's built and what's coming.
- `docs/adr/` - *why* each part is built the way it is (great for interviews).
- `CHANGELOG.md` - everything that's shipped.
