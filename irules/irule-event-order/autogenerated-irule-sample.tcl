when RULE_INIT {
    set static::client_ip "192.168.10.1"
    set static::json 1
}

when CLIENT_ACCEPTED {
    set counter 0
    set event_type "CLIENT_ACCEPTED"
    set sessionid "[IP::client_addr][TCP::client_port][IP::local_addr][TCP::local_port][expr { int(100000000 * rand()) }]" 
    binary scan [md5 $sessionid] H* md5_string trash
    set md5_string [string range $md5_string 12 20]
    set start_time [clock clicks -milliseconds]
    log local0. "virtual=[virtual], id=$md5_string, time=0, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        set json_log "\{ \"$md5_string\": \[\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"0\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when CLIENT_CLOSED {
    set counter [expr { $counter+1 }]
    set event_type "CLIENT_CLOSED"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\}\]\}"
        log local0. "$json_log"
    }
}

when HTTP_REQUEST {
    set counter [expr { $counter+1 }]
    set event_type "HTTP_REQUEST"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when HTTP_REQUEST_RELEASE {
    set counter [expr { $counter+1 }]
    set event_type "HTTP_REQUEST_RELEASE"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when HTTP_RESPONSE {
    set counter [expr { $counter+1 }]
    set event_type "HTTP_RESPONSE"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when HTTP_RESPONSE_RELEASE {
    set counter [expr { $counter+1 }]
    set event_type "HTTP_RESPONSE_RELEASE"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when HTTP_RESPONSE_CONTINUE {
    set counter [expr { $counter+1 }]
    set event_type "HTTP_RESPONSE_CONTINUE"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when HTTP_REQUEST_SEND {
    set counter [expr { $counter+1 }]
    set event_type "HTTP_REQUEST_SEND"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when HTTP_REQUEST_DATA {
    set counter [expr { $counter+1 }]
    set event_type "HTTP_REQUEST_DATA"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when CLIENT_DATA {
    set counter [expr { $counter+1 }]
    set event_type "CLIENT_DATA"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when HTTP_PROXY_REQUEST {
    set counter [expr { $counter+1 }]
    set event_type "HTTP_PROXY_REQUEST"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when HTTP_DISABLED {
    set counter [expr { $counter+1 }]
    set event_type "HTTP_DISABLED"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when SERVER_CLOSED {
    set counter [expr { $counter+1 }]
    set event_type "SERVER_CLOSED"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when SERVER_DATA {
    set counter [expr { $counter+1 }]
    set event_type "SERVER_DATA"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when SERVERSSL_DATA {
    set counter [expr { $counter+1 }]
    set event_type "SERVERSSL_DATA"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when SERVER_CONNECTED {
    set counter [expr { $counter+1 }]
    set event_type "SERVER_CONNECTED"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when CLIENTSSL_DATA {
    set counter [expr { $counter+1 }]
    set event_type "CLIENTSSL_DATA"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when CLIENTSSL_CLIENTCERT {
    set counter [expr { $counter+1 }]
    set event_type "CLIENTSSL_CLIENTCERT"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when CLIENTSSL_CLIENTHELLO {
    set counter [expr { $counter+1 }]
    set event_type "CLIENTSSL_CLIENTHELLO"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when CLIENTSSL_HANDSHAKE {
    set counter [expr { $counter+1 }]
    set event_type "CLIENTSSL_HANDSHAKE"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when CLIENTSSL_SERVERHELLO_SEND {
    set counter [expr { $counter+1 }]
    set event_type "CLIENTSSL_SERVERHELLO_SEND"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when SERVERSSL_CLIENTHELLO_SEND {
    set counter [expr { $counter+1 }]
    set event_type "SERVERSSL_CLIENTHELLO_SEND"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when SERVERSSL_HANDSHAKE {
    set counter [expr { $counter+1 }]
    set event_type "SERVERSSL_HANDSHAKE"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when SERVERSSL_SERVERHELLO {
    set counter [expr { $counter+1 }]
    set event_type "SERVERSSL_SERVERHELLO"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}

when LB_QUEUED {
    set counter [expr { $counter+1 }]
    set event_type "LB_QUEUED"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
} 

when LB_FAILED {
    set counter [expr { $counter+1 }]
    set event_type "LB_FAILED"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
} 

when LB_SELECTED {
    set counter [expr { $counter+1 }]
    set event_type "LB_SELECTED"
    set curtime [expr { [clock clicks -milliseconds] - $start_time }]
    log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
    if { $static::json } {
        append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
    }
}  