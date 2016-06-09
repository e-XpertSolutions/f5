when HTTP_REQUEST {
 switch -glob [HTTP::uri] {
  "*resourcetype=remote_desktop*" {    log local0. "virtual=[virtual], apm=[string range [ACCESS::session sid] [expr [string length [ACCESS::session sid]] - 10] end], user=[ACCESS::session data get session.logon.last.username], resourcetype=remote_desktop, [findstr [HTTP::uri] "resourcename=" 0 "\%"]" }
  "*f5-w-*" { 
  catch {
            set resource [binary format H* [findstr [HTTP::uri] "/f5-w-" 6 "\$\$"]]
            if { [table lookup -subtable PORTALACCESS "[ACCESS::session sid]:[ACCESS::session data get session.logon.last.username]:$resource"] eq "" } {
                table set -subtable PORTALACCESS "[ACCESS::session sid]:[ACCESS::session data get session.logon.last.username]:$resource" [clock format [clock seconds] -format %Y%m%d-%H%M%S] 3600
                log local0. "virtual=[virtual], apm=[string range [ACCESS::session sid] [expr [string length [ACCESS::session sid]] - 10] end], user=[ACCESS::session data get session.logon.last.username], resource_type=portal, resourcename=$resource"
            }           
        }
  }
 }
}