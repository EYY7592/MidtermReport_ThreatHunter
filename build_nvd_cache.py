import hashlib, os, json, time

cache_dir = "data"
os.makedirs(cache_dir, exist_ok=True)

def make_cache(pkg, vulns):
    h = hashlib.md5(pkg.encode()).hexdigest()[:12]
    path = os.path.join(cache_dir, f"nvd_cache_{pkg}_{h}.json")
    data = {"_cached_at": time.time(), "vulnerabilities": vulns, "total": len(vulns), "package": pkg}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[OK] {pkg} ({len(vulns)} CVEs) -> {path}")

make_cache("wordpress", [
    {"cve_id":"CVE-2022-21661","package":"WordPress","cvss_score":8.8,"severity":"HIGH","description":"WordPress <5.8.3 SQL injection via WP_Query","in_cisa_kev":False,"has_public_exploit":True},
    {"cve_id":"CVE-2021-29447","package":"WordPress","cvss_score":7.1,"severity":"HIGH","description":"WordPress 5.6-5.7 XXE via media upload","in_cisa_kev":False,"has_public_exploit":False},
])
make_cache("apache", [
    {"cve_id":"CVE-2021-41773","package":"Apache","cvss_score":9.8,"severity":"CRITICAL","description":"Apache 2.4.49 path traversal RCE via mod_cgi","in_cisa_kev":True,"has_public_exploit":True},
    {"cve_id":"CVE-2021-42013","package":"Apache","cvss_score":9.8,"severity":"CRITICAL","description":"Apache 2.4.50 path traversal bypass","in_cisa_kev":True,"has_public_exploit":True},
])
make_cache("phpmailer", [
    {"cve_id":"CVE-2021-3603","package":"PHPMailer","cvss_score":8.1,"severity":"HIGH","description":"PHPMailer 6.x RCE via crafted email","in_cisa_kev":False,"has_public_exploit":True},
])
make_cache("openssl", [
    {"cve_id":"CVE-2022-0778","package":"OpenSSL","cvss_score":7.5,"severity":"HIGH","description":"OpenSSL infinite loop in BN_mod_sqrt","in_cisa_kev":True,"has_public_exploit":False},
])
make_cache("mysql", [
    {"cve_id":"CVE-2021-2307","package":"MySQL","cvss_score":6.1,"severity":"MEDIUM","description":"MySQL 5.7 Server Package vulnerability","in_cisa_kev":False,"has_public_exploit":False},
])
make_cache("django", [
    {"cve_id":"CVE-2021-35042","package":"Django","cvss_score":9.8,"severity":"CRITICAL","description":"Django 3.1-3.2 SQL injection via QuerySet.order_by","in_cisa_kev":False,"has_public_exploit":True},
    {"cve_id":"CVE-2023-36053","package":"Django","cvss_score":7.5,"severity":"HIGH","description":"Django 3.2.x EmailValidator ReDoS","in_cisa_kev":False,"has_public_exploit":False},
])
make_cache("pillow", [
    {"cve_id":"CVE-2022-22817","package":"Pillow","cvss_score":9.8,"severity":"CRITICAL","description":"Pillow <9.0.1 RCE via PIL.ImageMath.eval","in_cisa_kev":False,"has_public_exploit":True},
    {"cve_id":"CVE-2023-44271","package":"Pillow","cvss_score":7.5,"severity":"HIGH","description":"Pillow <10.0.1 uncontrolled resource consumption","in_cisa_kev":False,"has_public_exploit":False},
])
make_cache("paramiko", [
    {"cve_id":"CVE-2023-48795","package":"paramiko","cvss_score":5.9,"severity":"MEDIUM","description":"Terrapin attack via SSH prefix truncation","in_cisa_kev":False,"has_public_exploit":True},
])
make_cache("celery", [
    {"cve_id":"CVE-2021-23727","package":"Celery","cvss_score":7.5,"severity":"HIGH","description":"Celery <5.2.2 privilege escalation","in_cisa_kev":False,"has_public_exploit":False},
])
make_cache("express", [
    {"cve_id":"CVE-2022-24999","package":"Express","cvss_score":7.5,"severity":"HIGH","description":"Express.js qs prototype pollution","in_cisa_kev":False,"has_public_exploit":False},
])
make_cache("lodash", [
    {"cve_id":"CVE-2021-23337","package":"lodash","cvss_score":7.2,"severity":"HIGH","description":"lodash <4.17.21 command injection via template","in_cisa_kev":False,"has_public_exploit":True},
    {"cve_id":"CVE-2020-8203","package":"lodash","cvss_score":7.4,"severity":"HIGH","description":"lodash <4.17.20 prototype pollution","in_cisa_kev":False,"has_public_exploit":True},
])
make_cache("jsonwebtoken", [
    {"cve_id":"CVE-2022-23539","package":"jsonwebtoken","cvss_score":8.1,"severity":"HIGH","description":"jsonwebtoken 8.x insecure algorithm selection","in_cisa_kev":False,"has_public_exploit":False},
    {"cve_id":"CVE-2022-23529","package":"jsonwebtoken","cvss_score":7.6,"severity":"HIGH","description":"jsonwebtoken private key injection","in_cisa_kev":False,"has_public_exploit":False},
])
make_cache("jenkins", [
    {"cve_id":"CVE-2024-23897","package":"Jenkins","cvss_score":9.8,"severity":"CRITICAL","description":"Jenkins <2.442 arbitrary file read RCE via CLI","in_cisa_kev":True,"has_public_exploit":True},
    {"cve_id":"CVE-2023-27898","package":"Jenkins","cvss_score":9.8,"severity":"CRITICAL","description":"Jenkins XSS leads to code execution","in_cisa_kev":False,"has_public_exploit":True},
])
make_cache("docker", [
    {"cve_id":"CVE-2021-41091","package":"Docker","cvss_score":6.3,"severity":"MEDIUM","description":"Docker 20.10 moby file permissions","in_cisa_kev":False,"has_public_exploit":False},
])
make_cache("kubernetes", [
    {"cve_id":"CVE-2022-3294","package":"Kubernetes","cvss_score":8.8,"severity":"HIGH","description":"K8s node address not validated enabling MITM","in_cisa_kev":False,"has_public_exploit":False},
    {"cve_id":"CVE-2021-25741","package":"Kubernetes","cvss_score":8.1,"severity":"HIGH","description":"K8s symlink exchange host filesystem access","in_cisa_kev":False,"has_public_exploit":False},
])
make_cache("helm", [
    {"cve_id":"CVE-2022-36055","package":"Helm","cvss_score":6.5,"severity":"MEDIUM","description":"Helm 3.x DoS via malformed chart archive","in_cisa_kev":False,"has_public_exploit":False},
])
make_cache("spring", [
    {"cve_id":"CVE-2022-22965","package":"Spring","cvss_score":9.8,"severity":"CRITICAL","description":"Spring4Shell: Spring Framework RCE via DataBinder","in_cisa_kev":True,"has_public_exploit":True},
])
make_cache("postgresql", [
    {"cve_id":"CVE-2022-2625","package":"PostgreSQL","cvss_score":8.0,"severity":"HIGH","description":"PostgreSQL extension script overwrite via ALTER EXTENSION","in_cisa_kev":False,"has_public_exploit":False},
])
make_cache("redis", [
    {"cve_id":"CVE-2022-0543","package":"Redis","cvss_score":10.0,"severity":"CRITICAL","description":"Redis Debian/Ubuntu Lua sandbox escape RCE","in_cisa_kev":True,"has_public_exploit":True},
])

count = len([f for f in os.listdir(cache_dir) if f.startswith("nvd_cache_")])
print(f"\nTotal cache files: {count}")
