+++
title = "DailyCookies"
description = "My random cookies"
date = "2023-0118"
aliases = ["dailycookies", "lessions"]
author = "Phong Vu"
+++


# Daily cookies

pdf printing solution

[Pricing - Browserless](https://www.browserless.io/pricing/)

[Puppeteer vs Selenium vs Playwright, a speed comparison](https://blog.checklyhq.com/puppeteer-vs-selenium-vs-playwright-speed-comparison/)

[https://github.com/mileszs/wicked_pdf](https://github.com/mileszs/wicked_pdf)

[https://github.com/transitive-bullshit/awesome-puppeteer](https://github.com/transitive-bullshit/awesome-puppeteer)

[How to convert HTML-to-PDF with Other Documentation - DocRaptor HTML to PDF Converter](https://docraptor.com/documentation)

## 02-01-2023

### External DNS across K8S clusters

- when installing External DNS (X-DNS) across clusters to manage same DNS zone(s)
    - pay attention to your `owner` setting
    
    [external-dns/types.go at d4523be44ce53069fa8371527a4f297fd1af94a1 · kubernetes-sigs/external-dns](https://github.com/kubernetes-sigs/external-dns/blob/d4523be44ce53069fa8371527a4f297fd1af94a1/pkg/apis/externaldns/types.go#L244)
    
    - otherwise, all of your DNS (managed by X-DNS) in other cluster will be **gone** 🙂
- reason: X-DNS using TXT to manage DNS records
    - e.g. `"heritage=external-dns,external-dns/owner=default,external-dns/resource=ingress/default/baby-php-type-juggling-inarray-111-ingress"`
- by default, `external-dns/owner` is set to `default`
    - if you leave it as-is, it will be same across clusters → DNS records will be override according to ingress / service deployed in a cluster

## 07-11-2022

### Database change process

- pre-check
    - table size
    - critical?
    - current traffic
    - lock table or not
- if critical + high traffic
    - **backup**
    - tern on maintanence mode → prevent unexpected write
    - run query

## 23-07-2022

### Linux SHM (tmpfs)

- shared memory, backed by memory **and swap**
- means of passing data between programs
- `tmpfs` appears as a mounted files system, but data located in memory
    - provide file system interface ~~with good performance~~

> `tmpfs` performance is deceptive. You will find workloads that are faster on tmpfs, and this is *not* because RAM is faster than disk: All filesystems are cached in RAM – the page cache! Rather, it is a sign that the workload is doing something that defeats the page cache. And of the worse things a process can do in this regard is syncing to disk way more often than necessary.
> 

[When should I use /dev/shm/ and when should I use /tmp/?](https://superuser.com/questions/45342/when-should-i-use-dev-shm-and-when-should-i-use-tmp)

- the perfomance point is deceptive because
    - write to fs doesn’t necessarily slower than to memory
    - whole fs is cached (buffer)
        - write is async until call `fsync()`
        - the only time that program notice the read speed
    - if your process is I/O bound → use tmpfs for better performance

## 12-07-2022

### Gitlab - repo checks

### Elasticsearch realm

- quick note on **authentication process**:
    - after authentication is completed, username (maybe also role name) will be added to sub-requests → for authorization
- core of authentication process
- use to distinguish user authentication by the means
    - e.g. LDAP, Kerberos, Reserved, **Native**, **File**
- commonly used Realm
    - `reserverd`: for internal user auth - Kibana, Beats
    - `native`: store hash of user password in `.security` index
    - `file`: same like native, but store hashed password in file
        - **tips:** this has practical use - in case `.security` index or external services (LDAP, Kerberos) become unavailable, **only user with `file` realm can authenticate with ES**

## 20-06-2022

### FastAPI return 307 redirect

```python
app.post("/v2/api-key/")
```

```bash
curl 'https://cvparser-core.rework.vn/v2/api-key' -X POST -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:101.0) Gecko/20100101 Firefox/101.0' -H 'Accept: application/json, text/plain, */*' -H 'Accept-Language: vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3' -H 'Accept-Encoding: gzip, deflate, br' -H 'Content-Type: application/json' -H 'Authorization: Bearer ${Bearer}' -H 'Origin: https://cvparser-admin.rework.vn' -H 'Connection: keep-alive' -H 'Referer: https://cvparser-admin.rework.vn/' -H 'Sec-Fetch-Dest: empty' -H 'Sec-Fetch-Mode: cors' -H 'Sec-Fetch-Site: same-site' -H 'TE: trailers' --data-raw '{"key":"wqr-1655742521358-ee1aae49-0048-4ac6-be14-fc691050aa75","limit":5}'
```

- note the `/` at the end of route
    - **pain**

## 19-06-2022

### HTTPs path is encrypted

- **The URL path and query string parameters are encrypted**, as are POST bodies.
- however, we still shouldn’t put credentials in HTTPS path
    - it is logged in browser history
    - be seen by someone glancing at the screen
    - can be leak by SNI

## 18-06-2022

### DNS - MX record priority

- increase P of mail delivery
- when client query mail server
    - return list of mail servers
    - try the one with highest priority
    - if it doesn’t make it
    - try the next one

### PTR records

- use for reverse DNS lookup
    - from IP → get domain

```bash
dig -x 1.1.1.1

; <<>> DiG 9.10.6 <<>> -x 1.1.1.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 64277
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;1.1.1.1.in-addr.arpa.		IN	PTR

;; ANSWER SECTION:
1.1.1.1.in-addr.arpa.	263	IN	PTR	one.one.one.one.

;; Query time: 10 msec
;; SERVER: 192.168.1.1#53(192.168.1.1)
;; WHEN: Sat Jun 18 00:30:44 +07 2022
;; MSG SIZE  rcvd: 78
```

- can be used to detect spam
    - receive different header/email from single server

> **Logging:** System logs typically record only IP 
addresses; a reverse DNS lookup can convert these into domain names for 
logs that are more human-readable.
> 

Along with this: Don't alert on CPU/Mem/Network. Those are false flags. Alert on pending pods. Alert on deployments that are stalled. Alert on your service health metrics. Leave the management of machines to your platform vendor, and use those in diagnosis of problems with your service, but "node has high CPU usage" is not a problem. "My service is slow" is a problem - And a potential cause of that problem is high CPU usage on a node, but high cpu usage isn't the thing you care about. 

Generally #2, install kube-state-metrics and monitor with prometheus. kube-state-metrics doesn't use events to make inferences about the state of the system.

Events are more of a 'nice to have', one of the core principles of Kubernetes is that events should not be actionable, i.e. you wouldn't respond or have an operator/controller taking actions based on events. They are really only 'hints' to the people trying to reason about what the state of the system is.

Logs are the same, they should never be actionable. Metrics should tell you what the current state of the system is, logs are there for analysis to understand why it was in that state

## 05-05-2022

### K8S secrets

- by default store unencrypted in `etcd`
- similar to `configmap`, except used for credentials (seperate for RBAC convenience)
    - *note on RBAC*: anyone has permission to create pods **implicitly** has permisson to read k8s secrets
- maximum size of single secret: **1 MB**
- 

## 09-04-2022

### SSL Handshake explained (again 😎)

- Overview:
    - client and server exchange `public_key` and agree on a common `session_key` to encrypt/decrypt data
    - ensure who ís who
- Concepts
    - SSL Cert: contain `server_public_key` and `server_info`, signed by a CA or self-signed
- Steps
    - TCP Handshake
    - ClientHello (supported protocol version, cipher, etc.)
    - ServerHello, Cert, ServHelloDone
        - Cert: SSL Cert
        - on_receive: verify cert come from server (using CA public keys)
    - ClientKeyExchange
        - send `premaster` (random string) to server
        - server use client `premaster` secret to generate session key
    
    > All TLS handshakes make use of asymmetric encryption (the public and private key), but not all will use the private key in the process of generating session keys
    > 
    
    ![Untitled](Daily%20cookies%20bb785df24fca4563ba9a19541fd2c647/Untitled.png)
    

## 29-03-2022

### Nginx ingres affinity

- mode:
    - `persistent`: maximum persistency - not redistribute session when scaling happens
    - `balanced`: >< with `persistent`
- affinity session: only support `cookie`
    - e.g. `INGRESSCOOKIE: "d7e757e232c266bde814567294e75d4f"`
    

## 17-03-2022

### Lambda cold start

- lambda cold start doesn’t really matter if you run background job
    - 1xx ms → 1s
- it may add up your delay if you serve API
    - but rarely happen with prod workload, bc requests keep lambda warm
        - except when it’s scaling or when you deploy new code
- AWS has a feature to help improve lambda perf called [provisioned concurrency](https://docs.aws.amazon.com/lambda/latest/dg/provisioned-concurrency.html)
    - yeah but it makes lambda less sexy (pricing issue)

### Interview lession learned

- if you don’t know, admit that you don’t know → it’s much harder than you think !
- try to ask interviewer about his opinion / solution (if he is willing to answer)

---

# Archived

18/03/2020

- process model based on:
    - resource grouping: group (separate) related resource
        - program text,
        - opening files
        - signals/signal handlers
    - thread of execution:
        - share process' resources
        - have their own resource to separate them
            - PC
            - register
            
- preempt: thread scheduling is managed by OS
- `asyncio` use cooperative multi tasking
    - user can make decision when/where ready to switch

- IO-bound
    - spend most of it's time doing IO operations
    - usually wait for external resource
        - esp. something much slower than CPU
    - *speed up*: overlapping the waiting for devices
- CPU-bound
    - spend most of it's time doing computation
    - intensive computation, not read/write data from/to file, net,...
    - *speed up*: do more computation at one time
- ThreadPoolExecutor = thread + pool + executor
    - manage thread if you don't need fine-grained control
- share data
    - must be thread-safe for data access
        - depend on how/when access data,...
        - queue
- `asyncio`
    - core concept:
        - event-loop
        - list maintaining state,... e.g. [ready, waiting]
    - never get interrupted without intentionally do it (giving control to control)
        - no worry thread-safe
    - coroutine vs subroutine
        
        ```bash
        Co-routine is sub-routine but persistent
        ```
        
        - subroutine stack bound to calling stack
        - coroutine stack separate (can resume/pause by any calling having access to it)
    

19/03/2020 

terraform

- declarative (specified what the desired states)
- client-only architecture
- cannot rollback
- should use implicit dependency
- `provisioner` is run only when resource is *created*
    
    ⇒ not replace configuration management
    
- `exec plan`: do exactly what it has told
    - tainted resource (provisioner failed) ⇒ not auto destroy tainted when apply the first time
        - doing so against exec plan
        - next time ⇒ destroy instance ⇒ exec provisioner
- provisioner are the last resort
    - use alternative wherever possible
    

22/03/2020 

python concurrency

- concurrency = (multiprocessing<para>, multithreading,

![Daily%20cookies%20bb785df24fca4563ba9a19541fd2c647/Untitled%201.png](Daily%20cookies%20bb785df24fca4563ba9a19541fd2c647/Untitled%201.png)

- coroutines:
    - have multi endpoint to start, resume function
        - *diff* with `generator`: generator generate data, `coroutine` can consume data
- asyncio: the Python package that provides a foundation and API for running and managing coroutines
- Async IO:
    - single threaded, single process design
    - **cooperative multitasking**

- why parameterized SQL query can prevent `sql injection`?
    - its not execute the query directly (give to special procedure...)
    - treat params as data (not query as when executed directly)

Web security

- when get untrusted input from someone ⇒ analyze carefully
    - `content standardization`

24/03/2020

- **exp** to debug python error in exception block, use `raise`, not `print`

25/03/2020

SMTP

![Daily%20cookies%20bb785df24fca4563ba9a19541fd2c647/Untitled%202.png](Daily%20cookies%20bb785df24fca4563ba9a19541fd2c647/Untitled%202.png)

- SMTP user to *send* email (push model)
    - POP3(pull) / IMAP ⇒ *receive* email
- User agent: Outlook, Mozilla,...

26/03/2020 

terraform

- use `data` source to read and query data
- use `lifecycle` hook ⇒ `create_before_destroy`
- use  `provisioner` to perform healthcheck,....

python concurrency

- other languages had (multiple) ways to approach threading concurrency
- python: GIL ⇒ threads cannot run parallel in multi core
    - perf affacted when need to utilize threads on multiple core
    

aws

- separate env by account (dev,staging,prod)
    - prod ⇒ mirror staging:
    - staging need to have "real" data (no need to large but *real*)
    - code need to hitting staging often ⇒ tested every sprints,...
- can use DNS as a service discovery
    - do not need agent, dependency,..
    - must somehow register service to registry (client or server side)
- cloud map (aws) service discovery
    - can map instance ⇒ service
    - ez to integrate with other aws service
    - query by dns, attribute,...
    - provide health check...

[https://segment.com/blog/the-million-dollar-eng-problem/](https://segment.com/blog/the-million-dollar-eng-problem/)

millions $ lession

- dynamodb ⇒ hosted version of Cassandra, support 2nd index, abstract replication, partition
    - pricing model works in terms of throughput
    - same key ⇒ same server, same partition
    - should uniformly distribute read/write
        - void 1 server constantly overload, other idle
    
    ![Daily%20cookies%20bb785df24fca4563ba9a19541fd2c647/Untitled%203.png](Daily%20cookies%20bb785df24fca4563ba9a19541fd2c647/Untitled%203.png)
    
    - dictates the number of partitions rather than the total throughput.
    - h

PGP

![pgp encryption](Daily%20cookies%20bb785df24fca4563ba9a19541fd2c647/Untitled%204.png)

pgp encryption

![pgp decryption](Daily%20cookies%20bb785df24fca4563ba9a19541fd2c647/Untitled%205.png)

pgp decryption

- speed of conventional key encrypt (use `session key` to encrypt data)
- convenience of public key distribution

Digital sig:

- RSA: instead of encrypt data using other people pub key
    - use your own priv key ⇒ if people can decrypt it using your pub ⇒ it's your content
- that may double size your data
    - use hash function
    - PGP: digest(hashed plain) + private key ⇒ signature
        - send sig + plaintext
        - decrypt sig using pub key
        - **TODO**
        

27/03/2020:

python decorator

- without args ⇒ `func = decor(func)`
    - decor need to return a *wrapper* of func
- with args ⇒ `func = decor(*args*,***kwargs)(func)`
    - decor need to return a function that `func` is a input ⇒ return *wrapper* of func
- `functools.wraps(f)` helps preserve information of the origin function (not wrapper)
- can be useful when debug (print args, return whenever a function is call)
    - *esp.* helpful when we don't directly call the function need to be debugged ourselves
    - *e.g*: *recursive*
- can use to throttle request (slow down func)
- it doesn't have to wrap function
    - *register* an existing function ⇒ return it unwrapped

30/03/2020: 

flask design decision

- explicit application object
    - fake multiple applications ⇒ unit testing,...
    - can create subclass
        - it not easy if the app object is created ahead of time
    - can init flask with the package __`name`__
        - use to access other resource relative to the package (templates,..)
        - can use CWD ⇒ not reliable (cuz it's process-wide)
    - `explicit is better than implicit`
- micro framework
- thread locals
    - uses thread local objects for session, extra object,...
    - harder to maintain for large application
    - flask aims for small traditional web app
    - 
    

samesite cookie

- def:
    - user enter `A.com`
    - `[A.com](http://a.com)` contains a cat picture which hosted on `B.com`
    - cookies of in browser for `[B.com](http://b.com)` would be sent to `B.com`
        - [B.com](http://b.com) maybe `vpbank.com/reset_password`
- it's dangerous but we still need it in other situation:
    - page ref to fb, google,..
    - ads,...
- SameSite
    - Strict: never send cross-site
    - Lax: send when user follow link, (click,...) - GET request
        - SameSite must be Secure

best practice to learn React

- [https://www.reddit.com/r/reactjs/comments/a8c0yp/what_is_the_best_way_to_learn_react/](https://www.reddit.com/r/reactjs/comments/a8c0yp/what_is_the_best_way_to_learn_react/)
- That example LoginForm component is likely passed a callback as a prop that it will call when the login is successful, probably passing that callback the username and/or any profile information. This can sound complex, but it isn't really - LoginForm ends up "dumb", because it doesn't know anything about the app. It knows how to login, and is given a callback to call once it has done so. "Dumb" (decoupled) means the opposite of complexity.
- thinking about how the UI should look at any given moment, rather than how to change it over time, eliminates a whole class of bugs.
- All React components must act like pure functions with respect to their props.

03/04/2020

**[exp]** evidence-based software engineering

- empirical
- what technology is appropriate in *specific situation*
- `asking the right question`
    - "is pair programming useful?" ⇒ not detail
    - "Does PP lead to improved code quality when practiced by professional dev?" ⇒ detailed
        - what intervention (PP)
        - what population
        

09/04/2020 

**[exp]** aws iam policy can be error without notification

- conditions contain invalid keys

14/04/2020 

**[exp]** presentation

- who is targeted attendee
    - end users need diff information from developers
    

21/04/2020

**[exp]** arch

- should go from and focus on business viewpoint first
    - where/how you got that desired CCU
- based on understanding of business
    - what scenarios(flow) cause what bottlenecks
        - it may not relevant to what customer thinks about their problem
        - what had customer done to figure out their problem
            - is there anything wrong with it
                - the way they're doing test,...
    - technology used
        - even "hype" techstack has its own problem
    - ops or dev need to be improved
        - external connection (port),...

26/04/2020 

service-oriented architecture and merging services

- does separating services benefit from separated service over performance issue (hopped network,...)
    - e.g scalability can be addressed only in one service
    - maintain security in standalone service
- how to implement new arch
    - if both services provide REST ⇒ can embed one service as the other's local library
    - A/B testing (ramp up)
    - perf analysis
        - dark canary
            - replicate, multiply real read-only prod traffic ⇒ test hosts
        - [https://sematext.com/blog/java-garbage-collection-logs/](https://sematext.com/blog/java-garbage-collection-logs/)
        

[https://www.digitalocean.com/community/tutorials/understanding-database-sharding?utm_campaign=Grokking Newsletter&utm_medium=email&utm_source=Revue newsletter](https://www.digitalocean.com/community/tutorials/understanding-database-sharding?utm_campaign=Grokking%20Newsletter&utm_medium=email&utm_source=Revue%20newsletter)

30/04/2020

github workflow

- can have multiple workflows in a repo
- triggering
    - can be scheduled (POSIX)
    - triggered by event (i.e. webhook event)
        - e.g create new branch, delete,...
        - issue is solved, reopened ,...
        - external event ⇒ send POST to github API
- workflow only triggered when use `personal token`
    - not by GITHUB Token ⇒ avoid recursive trigger
        - e.g. workflow run and make some event (push code,.._)
- can filtered by branches, tags and *paths*
- can use build matrix to test code across platform, OS, lang ver

```yaml
runs-on: ${{ matrix.os }}
strategy:
  matrix:
    os: [ubuntu-16.04, ubuntu-18.04]
    node: [6, 8, 10]
```

- reference to actions
    - can be in pub repo (or DockerHub)
    - if ref → private repo ⇒ workflow and action must be in same repo
    - use `check runs` to add status information to a commit
    
    [GitHub API: How to retrieve the combined pull request status from commit statuses, check runs, and GitHub Action results](https://dev.to/gr2m/github-api-how-to-retrieve-the-combined-pull-request-status-from-commit-statuses-check-runs-and-github-action-results-2cen)
    
    - `check runs` can be used to add more than binary (PASS/FAIL) information ⇒ can add context, additional information
        - **[exp]** use when have external CI tool
        

a project can have more than one CI tool when:

- developed by two or more separated teams
- team A trigger team B CI (by put status, hook,...)

- use minimum permission key. E.g:
    - when deploy app to deployment server ⇒ use *deploy keys* instead of personal secret
        - PK is attached to repo, not personal account each user
    
    `Avoid passing secrets between processes from the command line, whenever possible`
    
    - can be visible via `ps` command or captured by `security audit` event
- secret limit
    - can have up to 100 secrets
    - ≤ 64KB in size
        - if larger than that: store encrypted secret in repo, save decryption passphrase at secret on Githu
- artifact: share data btw jobs and save data after workflow completed
- github currently not have Rest API for upload/download artifact to use btw jobs
    - use S3 or other storage
- cache
    - use for github-hosted runner
    - do not store secret in cache
        - anyone with Read perm can create PR and read cache content
    - can access the cache in workflow triggered by `pull_request` or `push` , except for `pull_request` `closed`
    - workflow can access cache in current branch, the base branch, and default branch
    - only retent in 7 days and up to 5GB
- service container
    - when need to access database, cache,...
    - create service for each job
    - access to service depends on where the job is run
        - in container: connect via docker network ⇒ *simple*
        - on host: map docker port to container port
        
        ```yaml
        name: Redis Service Example
        on: push
        
        jobs:
          # Label of the container job
          runner-job:
            # You must use a Linux environment when using service containers or container jobs
            runs-on: ubuntu-latest
        
            # Service containers to run with `runner-job`
            services:
              # Label used to access the service container
              redis:
                # Docker Hub image
                image: redis
                #
                ports:
                  # Opens tcp port 6379 on the host and service container
                  - 6379:6379
        ```
        

- *circleci* vs *github*:
    - github both support container and runner
    - circleci has para test grouping (github does not)
- two types of action
    - Docker
    - Javascript
        - simplifies action code
        - faster than Docker container
- **security** with public repo on self-hosted runner
    - people can create PR and run code on the runner
- location of action
    - if develop for other people ⇒ keep in its own repo
        - decouple action version from app code version
    - otherwise, `.github`
- run action in Docker container
    - github action's metadata file can override some Dockerfile instructions
    - `USER`: must be default (`root`)
    - `WORK_DIR`: github set workdir in `GITHUB_WORKSPACE` and mount
    - Using the example Dockerfile above, GitHub will send the args configured in the action's metadata file as arguments to [entrypoint.sh](http://entrypoint.sh/)
- monitoring
    - log at `_diag` directory
    - journalctl log (service named with specific format)

note `deploy keys`

10/05/2020

[k8s] statefulset

headless service

- pod of stateless application is same ⇒ can expose using `ClusterIP`
- Stateful services (Kafka, db) is not
    - each instance do its own job
    - each instance in cluster has stable unique identity

PV and PVC

- separate to abstract: how the volume is provision VS how to "use" the volume
- `PV`: lo level of representation of storage

06/07/2020 

**[exp]** ca cert problem

1. run `curl-config --ca` and you will get something, e.g. `/etc/ssl/certs/ca-certificates.crt`, back it up(in case you need it)
2. go to [caExtract.html](https://curl.haxx.se/docs/caextract.html) download the latest `cacert.pem`, e.g. `cacert-2017-01-18.pem`
3. replace the original 'ca-certificates.crt' with the latest `cacert.pem` , e.g. `sudo mv cacert-2017-01-18.pem /etc/ssl/certs/ca-certificates.crt`
4. try to `yaourt -S tor-browser-en` again

ref:[[SOLVED] /etc/pki/tls/certs/ca-bundle.crt not present](https://bbs.archlinux.org/viewtopic.php?id=186138)

07/07/2020 

load avg. vs CPU utilization

- `load avg.`:
    - how many tasks are in kernel waiting queue or running
    - not just CPU, also Disk (I/O)
    - *short-lived tasks can be missed*
    - not divided by # of cores
    - >> 5 / core ⇒ HIGH
- `CPU utilization`
    - how busy CPU are
- high load avg. / low cpu utilization:
    - Lot of IO data stuck in `WAIT`
    - **storage issue**

15/07/2020 

Building container best practice

- pid 1 (zombie, orphan proc)
    - proper signal handlers for app
    - if use script for bootstrap ⇒ `exec` to replace pid
    - use specialized init system
        - `tini`: minimal for container env (signal handler, reap zombie proc,..)
            - run `docker --init`
            - install as entry point if use k8s
    - enable share process namespace (k8s) - in same pod
        - share file system
        - proc is visible from other container
        - *use* for special case: sidecar for log,...
- minimal size
    - do not install and remove in diff steps (overlay mechanism)
- sec
    - disable run-as-root
    - enable read-only mode for fs
- **inject** built files to other image
    - build ⇒ copy from build image ⇒ `scratch` image

08/06/2020

**Linux command to view proc using port**

- `lsof -i :[PORT]`: show proc *both* listening and established on port
- `ss`
    - show proc with detailed info
    - have intuitive filters
        - `ss -lptn 'dport = :443'`
- `nestat -nalpt`

02/02/2021 

- IaC is same with application code
    - have entropy, maintenance burden,...
    - keep thing simple

19/02/2021 

EFK setup:

- if you modify any `xpack.*` setting in kibana
    - the perf optimization will run → can hang
- to enable xpack without ssl:
    - setup ES in single-node mode
- use configmap to put config
    - not env var
    

20/02/2021 

Kubernetes liveness vs readiness

- liveness:
    - to determine when a pod need to be restarted
    - keep beating intervally
- readiness:
    - to determine use a pod as backend of a service
    - if not ready → remove from service load balancer

[Sharing - Docker 101’](https://www.notion.so/Sharing-Docker-101-0272f2850ae840c5ab9ee1edd73b5251)

[ES](https://www.notion.so/ES-6e708e196b5149e1be7badb962f42308)
