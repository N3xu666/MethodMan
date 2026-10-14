# Servers

> Part of [01 Web](../README.md) in the [Web Application Testing Cheatsheet](../README.md).

Web servers and servlet containers you will encounter in front of (or behind)
an application. Each file covers detection, enumeration, known CVEs,
exploitation patterns, misconfigurations, and post-exploitation. The
distinction matters: a reverse proxy (Nginx) hides a different attack surface
than an application server (Tomcat, Jetty) or the OS-level web server
(Apache, IIS).

---

## Files

| File | Type | Description |
|------|------|-------------|
| [Apache.md](./Apache.md) | Web server | Apache HTTP Server - `.htaccess`, mod_*, path traversal, CGI. |
| [IIS.md](./IIS.md) | Web server | Microsoft IIS - ASP.NET hosting, short-name (8.3) disclosure, WebDAV. |
| [Jetty.md](./Jetty.md) | Servlet container | Eclipse Jetty - embedded Java server, default servlets, admin contexts. |
| [Nginx.md](./Nginx.md) | Web server / reverse proxy | Nginx - alias traversal, misrouted locations, off-by-slash. |
| [Tomcat.md](./Tomcat.md) | Servlet container | Apache Tomcat - Manager/ Host-Manager, WAR deployment, AJP. |

---

> See [01 Web README](../README.md) for the full subcategory map.