import mechanize
import cookielib

#just the python browser to handle requests
br = mechanize.Browser()
cj = cookielib.LWPCookieJar()
cookieArray = []
globalLogging = False
br.set_cookiejar(cj)
br.set_handle_robots(False)
br.set_handle_refresh(False)
br.set_handle_redirect(True)
br.set_handle_redirect(mechanize.HTTPRedirectHandler)
br.addheaders = [('User-agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36')]
 
