# Web Investigation (CyberDefenders)

Network forensics lab, easy level. I used Wireshark for most of it and tshark when the GUI got painful.

The setup: an online bookstore got hacked and I had a pcap of the traffic. I had to figure out who did it, how they got in and what they did once they were in. I've left out the actual answers so this doesn't spoil the lab.

## Short version

The attacker scanned the site with Gobuster, found a search page vulnerable to SQL injection and used sqlmap to dump the database (customer data and the admin login table). Then they guessed their way into the admin panel and uploaded a PHP file, which is basically a backdoor into the server.

## How I got there

I opened Statistics > Conversations first. One IP had way more traffic than anything else, so that was my starting point. I looked it up to get the location and ISP.

There were tens of thousands of requests from that IP, so scrolling wasn't going to work. I counted the user agents instead:

```bash
tshark -r WebInvestigation.pcap -Y 'ip.src==<attacker> && http.request' -T fields -e http.user_agent | sort | uniq -c | sort -rn
```

Gobuster and sqlmap both showed up by name, which made the rest of the story a lot clearer. There were also a few Firefox requests in between, so they were poking around by hand too.

The SQL injection requests were all URL-encoded and unreadable in Wireshark, so I pulled them out and decoded them with a bit of Python:

```bash
tshark -r WebInvestigation.pcap -Y 'http.request.uri contains "search"' -T fields -e http.request.uri | python3 -c "import sys,urllib.parse;[print(urllib.parse.unquote(l.strip())) for l in sys.stdin]"
```

After decoding you can follow what sqlmap did step by step. It starts with a simple true/false test, then UNION queries against INFORMATION_SCHEMA to list databases and tables, then dumps the data. I got stuck for a bit on the random hex strings in the payloads. They turned out to be markers sqlmap adds so it can find its results in the page.

For the admin panel, I filtered out all the 404s from the scan, which left only a few paths. Some were default Apache folders like /icons/, but one was obviously the site's admin area.

The login part was the most interesting to me. Filtering on POST requests gave me just five packets: four logins and one request to the dashboard. The site was on plain HTTP, so the usernames and passwords were sitting right there in the form data. The attacker tried a few common passwords. My first guess was the first attempt, but it had failed. That made me realize I needed to figure out which attempt actually *worked*, not just which one was tried. The successful one is the attempt followed by a redirect into the dashboard.

The last POST was the upload. Expanding the multipart section showed a .php filename with Content-Type application/x-php. A bookstore admin should be uploading book images, not scripts.

## What would have caught this

- One IP getting thousands of 404s in a few minutes
- SQL keywords in URLs and a sqlmap user agent
- Failed admin logins followed by a successful one
- A PHP file coming through an upload form

And what would have prevented it: parameterized queries, a real admin password with lockout, HTTPS, and not letting the upload form accept scripts.

MITRE techniques: T1595.003 (wordlist scanning), T1190 (exploiting a public-facing app), T1110.001 (password guessing), T1078 (valid accounts), T1505.003 (web shell).

## What I learned

Conversations view is the fastest way into a big capture. User agents are useful but easy to fake, so they're a hint, not proof. And a login attempt alone doesn't mean much. You have to check what the server sent back.
