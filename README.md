Example usage. (it doesn't work in production environments atm)
This library depends on my string library. https://github.com/PlebPool/cstring


    openlog("cweb_server", LOG_CONS | LOG_PID | LOG_PERROR, LOG_USER);

    server_t* server = malloc(sizeof(server_t));

    server_init(server);

    unsigned short port = 8080;
    server_set_opt(server, S_O_PORT, &port);

    // File containing ascii art you want to display VVVVVVV
    cstring_t* ascii_art = cstring_create("./resources/ascii2");
    server_set_opt(server, S_O_ASCII_ART_LOCATION, ascii_art);
    cstring_destroy(ascii_art);

    cstring_t* static_resource = cstring_create("/var/www");
    server_set_opt(server, S_O_STATIC_RESOURCE_LOCATION, static_resource);
    cstring_destroy(static_resource);

    server_start(server); // Main loop.

    server_destroy(server);

    closelog();
    return 0;
