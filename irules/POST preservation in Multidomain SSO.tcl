###
# POST preservation feature
# for Virtual Server with Multidomain SSO configured
#
# require : APM
###

###
# Special notes
# To support POST preservation in v11 and v12,
# the administrator needs to configure special session variable assignment before the Allow ending in a Access policy
# session.server.body = Session Variable session.server.initial_req_body
# session.policy.result.redirect.url = Session Variable session.server.landinguri_base64
###

###
# Release notes
# * Basic support for POST preservation in v13
# * Add support for v11 and v12 environments
###

when RULE_INIT {
    set static::idp_host "idp.expertlab.net"
    set static::md_start_uri "/F5Networks-SSO-Req?SSO_ORIG_URI="

    # for v11.x and v12.x deployment
    # set static::body_var "session.server.body"

    # for v13.x deployment
    set static::body_var "session.server.initial_req_body"
}

when HTTP_REQUEST {
    if { ![ACCESS::session exists [HTTP::cookie MRHSession]] and [HTTP::host] eq "sp.expertlab.net" and !([HTTP::path] eq "/F5Networks-SSO-Resp") } {
        if { [HTTP::method] eq "POST" } {
            # save post data
            set ct [HTTP::header Content-Type]
            set uri [HTTP::uri]
            if { [URI::query $uri] != "" } {
                set uri $uri&ct=[URI::encode $ct]
            } else {
                set uri $uri?ct=[URI::encode $ct]
            }
            HTTP::respond 307 noserver Location "http://$static::idp_host$static::md_start_uri[URI::encode [b64encode http://[HTTP::host]$uri]]" Connection Close
            return
        } else {
            HTTP::respond 302 noserver Location "http://$static::idp_host$static::md_start_uri[URI::encode [b64encode http://[HTTP::host][HTTP::uri]]]" Connection Close
            return
        }
    }

    if { [ACCESS::session exists [HTTP::cookie MRHSession]] and [HTTP::header Referer] eq "http://idp.expertlab.net/my.policy" } {
        if { [ACCESS::session data get $static::body_var] != "" } {
            set ct [URI::decode [URI::query [HTTP::uri] ct]]
            set post 1
            HTTP::respond 200 content "<html><head><title></title></head><body onload=\"document.autosubmit.submit();\"> this page is used to hold your data while you are being authorized for your request.<br><br> you will be forwarded to continue the authorization process. if this does not happen automatically, please click the continue button below. <form name=\"autosubmit\" method=\"post\" action=\"[HTTP::path]\"> <input name=\"data\" type=\"hidden\" value=\"[b64encode [ACCESS::session data get $static::body_var]]\"> <input type=\"submit\" value=\"continue\"> </form></body></html>" noserver Content-Type "text/html"
            return
        }
    }

    if { [ACCESS::session exists [HTTP::cookie MRHSession]] and [info exists post] and $post } {
        if { [HTTP::method] eq "POST"} {
            HTTP::header replace Content-Type $ct
            set cl [HTTP::header Content-Length]
            HTTP::collect $cl
        }
    }
}

when HTTP_REQUEST_DATA {
    set payload [URI::decode [URI::query "/?[HTTP::payload]" data]]
    HTTP::payload replace 0 $cl [b64decode $payload]
}

###
# Provides a dummy forms for testing
###

when ACCESS_ACL_ALLOWED {
    HTTP::respond 200 content "<html><body><form action=\"/action_page.php\" method=\"post\"> <fieldset> <legend>Personal information:</legend> First name:<br> <input type=\"text\" name=\"firstname\" value=\"Mickey\"><br> Last name:<br> <input type=\"text\" name=\"lastname\" value=\"Mouse\"><br><br> <input type=\"submit\" value=\"Submit\"> </fieldset> </form></body></html>" Content-Type "text/html"
}
