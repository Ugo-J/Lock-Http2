#pragma once

#include "lockhttp2_headers.hpp"
#include "lockhttp2_structure.hpp"

// use the following pragma declaration to suppress the shift overflow warning
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshift-count-overflow"

// non blocking lock client function variants

// constructor with url string
lock_http2_client_nb::lock_http2_client_nb(std::string_view url){

    // we initialise our ssl ctx
    ssl_ctx = SSL_CTX_new(TLS_client_method());

    // NGHTTP2 INITIALISATION

    // we set our nghttp2 callbacks

    nghttp2_session_callbacks *callbacks = nullptr;

    // we initialise our local callback function
    int rv = nghttp2_session_callbacks_new(&callbacks);

    if(rv != 0){

        strcpy(error_buffer, "Failed to initialise nghttp2 callbacks");

        error = true;

    }

    // continue if no error
    if(!error){

        // Register our callbacks
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_cb);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_cb);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_cb);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_cb);

        // now we initialise our session client
        rv = nghttp2_session_client_new(&session, callbacks, this);

        // our callbacks are copied internally into our session object so we delete the callback pointer here
        nghttp2_session_callbacks_del(callbacks);

        if(rv != 0){
            
            strcpy(error_buffer, "Failed to create nghttp2 client session: ");

            // we concatenate the nghttp2 specific error
            strcat(error_buffer, nghttp2_strerror(rv));
        
            error = true;

        }

        // continue if no error
        if(!error){

            // we declare our nghttp2 settings struct and set our max concurrent streams in it
            nghttp2_settings_entry iv[1] = { {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, MAX_CONCURRENT_STREAMS} };

            // we submit our settings
            rv = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, std::size(iv));

            if(rv != 0){

                strcpy(error_buffer, "Failed to submit initial Settings frame: ");

                // we concatenate the nghttp2 specific error
                strcat(error_buffer, nghttp2_strerror(rv));
            
                error = true;

            }
            
            // if we get here without error, the connection magic "PRI * HTTP/2.0..." and our SETTINGS frame are sitting inside the internal nghttp2 memory buffer. They will not go anywhere until we execute our outbound serialization/network pump (via nghttp2_session_mem_send2).

        }

    }

    // NGHTTP2 INITIALISATION END
    
    // check if url is a https:// endpoint, check case insensitively - we only implement the https client
        
    if(url.compare(0, 8, "https://") == 0){
    
        int protocol_prefix_len = strlen("https://");

        int base_url_length = url.size() - protocol_prefix_len; // saves the length of the url without the https:// prefix
        
        // size of required memory in bytes to store the base url and the port number
        int req_mem = base_url_length + 5; // we add an extra 5 bytes to the base url length to accomodate for the port number we would append before passing ths url to bio new connect

        // SSL members initialisations
        c_bio = BIO_new_ssl_connect(ssl_ctx); // creates a new bio ssl object
        BIO_get_ssl(c_bio, &c_ssl); // get the SSL structure component of the ssl bio for per instance SSL settings
        if(c_ssl == NULL){
            
            strcpy(error_buffer, "Error fetching SSL structure pointer ");
                    
            error = true;
            
        }
    
        if(!error){ // the constructor continues only if there was no error fetching the ssl pointer

            // URL copy 
            if(req_mem < url_static_array_length){ // static memory large enough
            
                url.copy(c_url_static, base_url_length, protocol_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the static character array
            
                c_url_static[base_url_length] = '\0'; // null-terminate the string
            
                c_url = c_url_static;
            
            }
            else if(req_mem < size_of_allocated_url_memory){ // store in already allocated dynamic memory
                
                url.copy(c_url_new, base_url_length, protocol_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the already allocated character array
            
                c_url_new[base_url_length] = '\0'; // null-terminate the string
            
                c_url = c_url_new;
                
            
            }
            else{ // neither static or dynamic memory is large enough, we test whether memory has already been allocated or not 
                
                if(c_url_new == NULL){ // memory has not yet been allocated
                    
                    c_url_new = new(std::nothrow) char[req_mem]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
                
                
                    if(c_url_new == NULL){
                        
                        strncpy(error_buffer, "Error allocating heap memory for lock_http2_client url parameter ", error_buffer_array_length);
                        
                        error = true;
                        
                    }
                    else{
                        
                        size_of_allocated_url_memory = req_mem;    
                            
                        url.copy(c_url_new, base_url_length, protocol_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
            
                        c_url_new[base_url_length] = '\0';
            
                        c_url = c_url_new;
                    
                    }
            
                }
                else{ // memory has been allocated but still isn't large enough
                    
                    delete [] c_url_new; // delete the already allocated memory
                    
                    // heap memory allocation for urls larger than the static array length
                    c_url_new = new(std::nothrow) char[req_mem]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
                
                    
                    if(c_url_new == NULL){
                        
                        strcpy(error_buffer, "Error allocating heap memory for lock_http2_client url parameter ");
                        
                        error = true;
                        
                    }
                    else{
                        
                        size_of_allocated_url_memory = req_mem;    
                            
                        url.copy(c_url_new, base_url_length, protocol_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
                
                        c_url_new[base_url_length] = '\0';

                        c_url = c_url_new;
                    
                    }
                
                }

            }
            
            if(!error){ // checks if there was any error allocating memory, that is if that part of the code was executed. The constructor only continues if there was no error 
                
                // we append our port number - we use strcat here because the array length check already checks that we have enough space in the array to accomodate for the port number
                strcat(c_url, ":443");

                // set the websocket url(port included)
                BIO_set_conn_hostname(c_bio, c_url);
                
                // set SSL mode to retry automatically should SSL connection fail
                SSL_set_mode(c_ssl, SSL_MODE_AUTO_RETRY);

                // we set our alpn protos on our ssl object to indicate that this handle only negotiates http2 protocol
                SSL_set_alpn_protos(c_ssl, (const unsigned char *)"\x02h2", 3);
        
            }
        
        }
    
    }
    else{ // not a valid http endpoint
        
        strcpy(error_buffer, "Supplied URL parameter is not a valid https endpoint");
                
        error = true;
        
    }
    // initialisation of BIO and SSL structures end
    
    if(!error){ // only continue if no error
        
        int search_start_index = 8; // we store the index where we would begin the host name search from, we start searching from after the https:// protocol prefix
            
        int host_name_len = url.size() - search_start_index;

        if( host_name_len < host_static_array_length ){ // static array is large enough
        
            url.copy(c_host_static, host_name_len, search_start_index);
        
            c_host_static[host_name_len] = '\0';
        
            c_host = c_host_static;
        
        }
        else if( host_name_len < size_of_allocated_host_memory){ // dynamic memory is large enough
            
            url.copy(c_host_new, host_name_len, search_start_index);
        
            c_host_new[host_name_len] = '\0';
        
            c_host = c_host_new;
            
        }
        else{ // neither static or already allocated memory is large enough, we test the two possible cases
            
            if(c_host_new == NULL){ // memory has not been allocated yet 
            
                c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
        
        
                if(c_host_new == NULL){
            
                    strcpy(error_buffer, "Error allocating heap memory for server host name ");
                
                    error = true;    
            
                }
                else{
                    
                    size_of_allocated_host_memory = host_name_len + 1;
                    
                    url.copy(c_host_new, host_name_len, search_start_index);
        
                    c_host_new[host_name_len] = '\0';
        
                    c_host = c_host_new;
        
                }
            
            }
            else{ // memory has been allocated but it still isn't sufficient
                
                delete [] c_host_new; // delete the previously allocated memory
                
                c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
        
        
                if(c_host_new == NULL){
            
                    strcpy(error_buffer, "Error allocating heap memory for server host name ");
                
                    error = true;    
            
                }
                else{
                    
                    size_of_allocated_host_memory = host_name_len + 1;
                    
                    url.copy(c_host_new, host_name_len, search_start_index);
        
                    c_host_new[host_name_len] = '\0';
        
                    c_host = c_host_new;

        
                }
            
            }
            
        }
        
        if(!error){ // only continue if no error
        
            // we set the host name we wish to connect to for server name identification(SNI).
            if(!SSL_set_tlsext_host_name(c_ssl, c_host)){
            // we test the return value. SSL_set_tlsext_host_name returns 0 on error and 1 on success
                
                strcpy(error_buffer, "Error setting up Lock client for SNI TLS extension");
                    
                error = true;
            
            }
            
            if(!error){ // only continue if no error

                // Set the BIO to non-blocking
                BIO_set_nbio(c_bio, 1);

                // make the connection
                while(BIO_do_connect(c_bio) <= 0){
                    
                    if(BIO_should_retry(c_bio)){
                    // getting here the read request would block so we just return

                        continue;

                    }
                    else{
                        
                        strcpy(error_buffer, "Error connecting to WebSocket host ");
                    
                        error = true;

                        break;

                    }

                }
                
                if(!error){ // only continue if no error

                    // we check the protocol that was negotiated, if it is not http2 we disconnect our BIO handle and set our error flag
                    unsigned int protocol_len = 0;
                    const unsigned char* protocol = nullptr;

                    SSL_get0_alpn_selected(c_ssl, &protocol, &protocol_len);

                    if(protocol_len != 2 || memcmp(protocol, "h2", 2) != 0){

                        strcpy(error_buffer, "h2 protocol was not negotiated");

                        error = true;

                        // we reset our bio
                        BIO_reset(c_bio);
                    }

                    // only continue if no error
                    if(!error){

                        // we set our http headers

                        // we set our method pseudo header with nullptr value so we can get the index to update it with
                        method_index = set_header(":method", nullptr);

                        // we set our path pseudo header with nullptr value so we can get the index to update it with
                        path_index = set_header(":path", nullptr);

                        // we set our scheme pseudo header - this doesn't change after connecting to the server
                        set_header(":scheme", const_cast<char*>("https"));

                        // we set our authority pseudo header - this also doesn't change after connecting to the server
                        set_header(":authority", c_host);

                    }
                
                }
            
            }
    
        }
    
    }

}

// constructor that binds to a network interface
lock_http2_client_nb::lock_http2_client_nb(std::string_view url, in_addr* interface_address, char* interface_name){

    // we initialise our ssl ctx
    ssl_ctx = SSL_CTX_new(TLS_client_method());

    // NGHTTP2 INITIALISATION

    // we set our nghttp2 callbacks

    nghttp2_session_callbacks *callbacks = nullptr;

    // we initialise our local callback function
    int rv = nghttp2_session_callbacks_new(&callbacks);

    if(rv != 0){

        strcpy(error_buffer, "Failed to initialise nghttp2 callbacks");

        error = true;

    }

    // continue if no error
    if(!error){

        // Register our callbacks
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_cb);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_cb);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_cb);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_cb);

        // now we initialise our session client
        rv = nghttp2_session_client_new(&session, callbacks, this);

        // our callbacks are copied internally into our session object so we delete the callback pointer here
        nghttp2_session_callbacks_del(callbacks);

        if(rv != 0){
            
            strcpy(error_buffer, "Failed to create nghttp2 client session: ");

            // we concatenate the nghttp2 specific error
            strcat(error_buffer, nghttp2_strerror(rv));
        
            error = true;

        }

        // continue if no error
        if(!error){

            // we declare our nghttp2 settings struct and set our max concurrent streams in it
            nghttp2_settings_entry iv[1] = { {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, MAX_CONCURRENT_STREAMS} };

            // we submit our settings
            rv = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, std::size(iv));

            if(rv != 0){

                strcpy(error_buffer, "Failed to submit initial Settings frame: ");

                // we concatenate the nghttp2 specific error
                strcat(error_buffer, nghttp2_strerror(rv));
            
                error = true;

            }
            
            // if we get here without error, the connection magic "PRI * HTTP/2.0..." and our SETTINGS frame are sitting inside the internal nghttp2 memory buffer. They will not go anywhere until we execute our outbound serialization/network pump (via nghttp2_session_mem_send2).

        }

    }

    // NGHTTP2 INITIALISATION END
    
    // check if url is a https:// endpoint, check case insensitively - we only implement the https client
        
    if(url.compare(0, 8, "https://") == 0){
    
        int protocol_prefix_len = strlen("https://");

        int base_url_length = url.size() - protocol_prefix_len; // saves the length of the url without the https:// prefix
        
        // size of required memory in bytes to store the base url and the port number
        int req_mem = base_url_length + 5; // we add an extra 5 bytes to the base url length to accomodate for the port number we would append
        
        // URL copy 
        if(req_mem < url_static_array_length){ // static memory large enough
        
            url.copy(c_url_static, base_url_length, protocol_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the static character array
        
            c_url_static[base_url_length] = '\0'; // null-terminate the string
        
            c_url = c_url_static;
        
        }
        else if(req_mem < size_of_allocated_url_memory){ // store in already allocated dynamic memory
        
            url.copy(c_url_new, base_url_length, protocol_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the already allocated character array
        
            c_url_new[base_url_length] = '\0'; // null-terminate the string
        
            c_url = c_url_new;
            
        
        }
        else{ // neither static or dynamic memory is large enough, we test whether memory has already been allocated or not
            
            if(c_url_new == NULL){ // memory has not yet been allocated
                
                c_url_new = new(std::nothrow) char[req_mem]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
                if(c_url_new == NULL){
                    
                    strcpy(error_buffer, "Error allocating heap memory for lock_http2_client url parameter ");
                    
                    error = true;
                    
                }
                else{
                    
                    size_of_allocated_url_memory = req_mem;    
                        
                    url.copy(c_url_new, base_url_length, protocol_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
        
                    c_url_new[base_url_length] = '\0';
        
                    c_url = c_url_new;
                
                }
        
            }
            else{ // memory has been allocated but still isn't large enough
                
                delete [] c_url_new; // delete the already allocated memory
                
                // heap memory allocation for urls larger than the static array length
                c_url_new = new(std::nothrow) char[req_mem]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
                
                if(c_url_new == NULL){
                    
                    strcpy(error_buffer, "Error allocating heap memory for lock_http2_client url parameter ");
                    
                    error = true;
                    
                }
                else{
                    
                    size_of_allocated_url_memory = req_mem;    
                        
                    url.copy(c_url_new, base_url_length, protocol_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
            
                    c_url_new[base_url_length] = '\0';

                    c_url = c_url_new;
                
                }
            
            }

        }

        if(!error){

            // we append our port number - we use strcat here because the array length check already checks that we have enough space in the array to accomodate for the port number
            strcat(c_url, ":443");

            int search_start_index = 8; // we store the index where we would begin the host name search from, we start searching from after the https:// protocol prefix
            
            int host_name_len = url.size() - search_start_index;

            if( host_name_len < host_static_array_length ){ // static array is large enough
            
                url.copy(c_host_static, host_name_len, protocol_prefix_len);
            
                c_host_static[host_name_len] = '\0';
            
                c_host = c_host_static;
            
            }
            else if( host_name_len < size_of_allocated_host_memory){ // dynamic memory is large enough
                
                url.copy(c_host_new, host_name_len, protocol_prefix_len);
            
                c_host_new[host_name_len] = '\0';
            
                c_host = c_host_new;
                
            }
            else{ // neither static or already allocated memory is large enough, we test the two possible cases
                
                if(c_host_new == NULL){ // memory has not been allocated yet 
                
                    c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
            
                    if(c_host_new == NULL){
                
                        strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                    
                        error = true;    
                
                    }
                    else{
                        
                        size_of_allocated_host_memory = host_name_len + 1;
                        
                        url.copy(c_host_new, host_name_len, protocol_prefix_len);
            
                        c_host_new[host_name_len] = '\0';
            
                        c_host = c_host_new;
            
                    }
                
                }
                else{ // memory has been allocated but it still isn't sufficient
                    
                    delete [] c_host_new; // delete the previously allocated memory
                    
                    c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
            
                    if(c_host_new == NULL){
                
                        strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                    
                        error = true;    
                
                    }
                    else{
                        
                        size_of_allocated_host_memory = host_name_len + 1;
                        
                        url.copy(c_host_new, host_name_len, protocol_prefix_len);
            
                        c_host_new[host_name_len] = '\0';
            
                        c_host = c_host_new;

            
                    }
                
                }
                
            }

            // we create a local char array to hold the port extracted from the url
            const int MAX_CHAR_FOR_PORT = 8; // a port number can have a maximum of 5 characters because port numbers are 16 bit integers
            char c_port[MAX_CHAR_FOR_PORT];

            // we store our port number which is 443 for a https connection
            std::string_view port = "443";

            // we now copy the derived port into char array
            int num_of_chars_copied = port.copy(c_port, port.size());

            // we null terminate the c_port array
            c_port[num_of_chars_copied] = '\0';

            // now we can call the connect to server function that would return the configured socket file descriptor
            int sock = connect_to_server(c_host, c_port, interface_address, interface_name);

            if(error == false){
            // only continue if no error

                // we create an SSL object for this lock client instance
                SSL *c_ssl = SSL_new(ssl_ctx);
                if(c_ssl == NULL){
                    
                    strcpy(error_buffer, "Error creating SSL structure ");
                    error = true;

                }
            
                if(!error){
                // continue if no error

                    // Set SNI
                    SSL_set_tlsext_host_name(c_ssl, c_host);

                    // set SSL mode to retry automatically should SSL connection fail
                    SSL_set_mode(c_ssl, SSL_MODE_AUTO_RETRY);

                    // we set our alpn protos on our ssl object to indicate that this handle only negotiates http2 protocol
                    SSL_set_alpn_protos(c_ssl, (const unsigned char *)"\x02h2", 3);

                    // Create BIO for this socket
                    BIO* sock_bio = BIO_new_socket(sock, BIO_NOCLOSE);
                    if(!sock_bio){
                        
                        SSL_free(c_ssl);
                        ::close(sock);
                        strcpy(error_buffer, "Error creating BIO structure from socket");          
                        error = true;
                    }

                    if(!error){
                    // continue if no error

                        // now we create an SSL BIO
                        BIO* ssl_bio = BIO_new(BIO_f_ssl());
                        BIO_set_ssl(ssl_bio, c_ssl, BIO_CLOSE);

                        // Chain ssl_bio and sock_bio together
                        c_bio = BIO_push(ssl_bio, sock_bio);

                        // initialize SSL connection
                        SSL_set_connect_state(c_ssl);  // Set as client

                        // perform tls handshake
                        if(BIO_do_handshake(c_bio) <= 0){

                            BIO_free_all(c_bio); // this function throws segmentation fault when called without any network connection but to get here the connection has been established
                            strcpy(error_buffer, "TLS handshake failed");          
                            error = true;
                        }

                        if(!error){
                        // continue if no error
                            
                            // we check the protocol that was negotiated, if it is not http2 we disconnect our BIO handle and set our error flag
                            unsigned int protocol_len = 0;
                            const unsigned char* protocol = nullptr;

                            SSL_get0_alpn_selected(c_ssl, &protocol, &protocol_len);

                            if(protocol_len != 2 || memcmp(protocol, "h2", 2) != 0){

                                strcpy(error_buffer, "h2 protocol was not negotiated");

                                error = true;

                                // we reset our bio
                                BIO_reset(c_bio);
                            }

                            // only continue if no error
                            if(!error){

                                // we set our http headers

                                // we set our method pseudo header with nullptr value so we can get the index to update it with
                                method_index = set_header(":method", nullptr);

                                // we set our path pseudo header with nullptr value so we can get the index to update it with
                                path_index = set_header(":path", nullptr);

                                // we set our scheme pseudo header - this doesn't change after connecting to the server
                                set_header(":scheme", const_cast<char*>("https"));

                                // we set our authority pseudo header - this also doesn't change after connecting to the server
                                set_header(":authority", c_host);

                            }

                        }
                    }
                }
            }
        }
    }
    else{ // not a valid http endpoint
        
        strcpy(error_buffer, "Supplied URL parameter is not a valid https endpoint");
                
        error = true;
        
    }

}

// parameterless constructor
lock_http2_client_nb::lock_http2_client_nb(){
    
    // initialise ssl ctx
    ssl_ctx = SSL_CTX_new(TLS_client_method());

    // NGHTTP2 INITIALISATION

    // we set our nghttp2 callbacks

    nghttp2_session_callbacks *callbacks = nullptr;

    // we initialise our local callback function
    int rv = nghttp2_session_callbacks_new(&callbacks);

    if(rv != 0){

        strcpy(error_buffer, "Failed to initialise nghttp2 callbacks");

        error = true;

    }

    // continue if no error
    if(!error){

        // Register our callbacks
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_cb);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_cb);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_cb);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_cb);

        // now we initialise our session client
        rv = nghttp2_session_client_new(&session, callbacks, this);

        // our callbacks are copied internally into our session object so we delete the callback pointer here
        nghttp2_session_callbacks_del(callbacks);

        if(rv != 0){
            
            strcpy(error_buffer, "Failed to create nghttp2 client session: ");

            // we concatenate the nghttp2 specific error
            strcat(error_buffer, nghttp2_strerror(rv));
        
            error = true;

        }

        // continue if no error
        if(!error){

            // we declare our nghttp2 settings struct and set our max concurrent streams in it
            nghttp2_settings_entry iv[1] = { {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, MAX_CONCURRENT_STREAMS} };

            // we submit our settings
            rv = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, std::size(iv));

            if(rv != 0){

                strcpy(error_buffer, "Failed to submit initial Settings frame: ");

                // we concatenate the nghttp2 specific error
                strcat(error_buffer, nghttp2_strerror(rv));
            
                error = true;

            }
            
            // if we get here without error, the connection magic "PRI * HTTP/2.0..." and our SETTINGS frame are sitting inside the internal nghttp2 memory buffer. They will not go anywhere until we execute our outbound serialization/network pump (via nghttp2_session_mem_send2).

        }

    }
    
}

// destructor
lock_http2_client_nb::~lock_http2_client_nb(){
    
    // close the websocket connection if any
    if(client_state == OPEN){
        
        close();
        
    }

    // we free our nghttp2 session
    nghttp2_session_del(session);
    
    // free url heap memory - this only runs if dynamic memory allocation is used to store the url
    if(!(c_url_new == NULL)){
        
        delete [] c_url_new;
        
    }
    
    // free host heap memory if host string was stored in dynamic memory
    if(!(c_host_new == NULL)){
        
        delete [] c_host_new;
        
    }

    // free the ssl bio chain
    BIO_free_all(c_bio);
    
    // we free all allocated data memory if any - heap memory for data starts from index NUM_OF_STATIC_ARRAYS of our metadata array
    for(int i = NUM_OF_STATIC_ARRAYS; i<MAX_CONCURRENT_STREAMS; i++){

        // end the loop if we reach a nullptr
        if(metadata[i].data_array == nullptr) break;

        // we free this memory
        delete [] metadata[i].data_array;

    }
    
}

int lock_http2_client_nb::on_frame_recv_cb(nghttp2_session *session, const nghttp2_frame *frame, void *user_data){

    lock_http2_client_nb* client = static_cast<lock_http2_client_nb*>(user_data);
    return client->handle_frame_recv(frame);
}

int lock_http2_client_nb::on_data_chunk_recv_cb(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data){

    lock_http2_client_nb* client = static_cast<lock_http2_client_nb*>(user_data);
    return client->handle_data_chunk(flags, stream_id, data, len);

}

int lock_http2_client_nb::on_stream_close_cb(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data){

    lock_http2_client_nb* client = static_cast<lock_http2_client_nb*>(user_data);
    return client->handle_stream_close(stream_id, error_code);
}

long lock_http2_client_nb::send_body_provider_cb(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data){

    const char* data_start = static_cast<const char*>(source->ptr);
    int& remaining_bytes = source->fd; // we use fd to keep track of how much data we still have to send

    if(remaining_bytes == 0){

        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return 0;

    }

    // we copy our data into the nghttp2 internal buffer denoted by buf, the supplied length parameter holds the array size of the nghttp internal buffer so it is the max amount of data we can copy into that buffer
    size_t to_copy = std::min(length, static_cast<size_t>(remaining_bytes));
    std::memcpy(buf, data_start, to_copy);
    
    // we increment our source ptr so we start copying from the next unsent byte when next this callback is called
    source->ptr = const_cast<char*>(data_start + to_copy);

    // we decrement our remaining bytes which is a reference to source->fd
    remaining_bytes -= to_copy;

    if(remaining_bytes == 0){

        *data_flags |= NGHTTP2_DATA_FLAG_EOF;

    }

    return static_cast<long>(to_copy);
}

int lock_http2_client_nb::on_header_cb(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data){

    lock_http2_client_nb* client = static_cast<lock_http2_client_nb*>(user_data);

    // we fetch our stream data for this request
    meta_data* stream_metadata = static_cast<meta_data*>(nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));

    return client->recv_header(reinterpret_cast<const char*>(name), namelen, reinterpret_cast<const char*>(value), valuelen, (stream_metadata != nullptr) ? stream_metadata->user_id : -1);

}

int lock_http2_client_nb::handle_frame_recv(const nghttp2_frame *frame){

    // we use this switch case to handle different header types
    /* switch(frame->hd.type){

        case NGHTTP2_HEADERS:

            if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM){

                std::cout<<"[Stream "<<frame->hd.stream_id<<"] Response finished (Headers only).\n";
            }

            break;

        case NGHTTP2_SETTINGS:

            std::cout<<"SETTINGS frame received from server.\n";
            break;

        case NGHTTP2_PING:

            std::cout<<"PING frame received from server.\n";
            break;

    } */

    return 0;
}

int lock_http2_client_nb::default_header_receive(const char* name, size_t namelen, const char* value, size_t valuelen, int user_id){

    // std::cout<<"[User Id "<<user_id<<"] Header -> "<<name<<": "<<value<<"\n";

    return 0;

}

int lock_http2_client_nb::handle_data_chunk(uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len){

    // we fetch our stream data for this request
    meta_data* stream_metadata = static_cast<meta_data*>(nghttp2_session_get_stream_user_data(session, stream_id));

    // we check that our stream metadata isn't null, if it is we run nothing and just return
    if(stream_metadata != nullptr){

        // getting here our stream metadata isn't null so we continue

        // we fetch the length of data stored for this stream which we get by computing cursor - data array
        int length_of_data = stream_metadata->cursor - stream_metadata->data_array;

        // we compute the capacity needed to store this data'
        int capacity = length_of_data + static_cast<int>(len);

        // now we check if the capacity needed is > our data array capacity
        if(capacity > stream_metadata->array_size){

            // getting here copying this data chunk to our data array would cause our data array to overflow so we allocate a capacity that is twice what we would need to store this data in our data array

            // we fetch a new slot for this stream with enough capacity
            int slot = acquire_heap(capacity * 2);

            // we check if the acquire heap request was successful
            if(slot < 0){

                // getting here the acquire heap request failed so we free the current slot this thread uses and set the stream user data pointer to null so subsequent calls to handle data chunk ignores it

                // we release the slot used by this stream
                release(stream_metadata->array_index);

                // we set the stream user data to nullptr
                nghttp2_session_set_stream_user_data(session, stream_id, nullptr);

                // we set our lock client error flag
                strcpy(error_buffer, "Error acquiring heap slot for stream after exceeding initial slot capacity");

                error = true;

                // we return from this function
                return -1;

            }

            // getting here the returned slot is valid so we copy our data to the new slot
            std::memcpy(metadata[slot].data_array, stream_metadata->data_array, length_of_data);

            // we increment our new slot cursor
            metadata[slot].cursor += length_of_data;

            // we copy our user supplied id to our new slot
            metadata[slot].user_id = stream_metadata->user_id;

            // we release the old slot used by this stream back to our data array
            release(stream_metadata->array_index);

            // we set the stream user data to the new slot
            nghttp2_session_set_stream_user_data(session, stream_id, static_cast<void*>(&metadata[slot]));

            // we point our local stream metadata pointer to this new slot so this function can continue seamlessly
            stream_metadata = &metadata[slot];

        }

        // we copy this data into the data array for this stream using the cursor
        std::memcpy(stream_metadata->cursor, data, len);

        // we increment our cursor
        stream_metadata->cursor += len;

    }
    
    return 0;

}

int lock_http2_client_nb::handle_stream_close(int32_t stream_id, uint32_t error_code){

    if(error_code == NGHTTP2_NO_ERROR){

        // std::cout<<"[Stream "<<stream_id<<"] Closed successfully.\n";

        // we fetch our stream metadata for this stream
        meta_data* stream_metadata = static_cast<meta_data*>(nghttp2_session_get_stream_user_data(session, stream_id));

        // we null terminate our received data
        *(stream_metadata->cursor) = '\0';

        // since this is the end of our stream we call our recv data function - our data length is gotten by cursor - data array
        recv_data(stream_metadata->data_array, stream_metadata->cursor - stream_metadata->data_array, stream_metadata->array_size, stream_metadata->user_id);

        // now we release the data array we used for this stream, the data array slot is stored in the array index variable of the stream metadata
        release(stream_metadata->array_index);

    }
    else{

        std::cout<<"[Stream "<<stream_id<<"] Closed with error code: "<<error_code<<"\n";
    }
    
    return 0;

}

inline bool lock_http2_client_nb::status(){ // returns the error status of a lock_http2_client instance
    
    return error;
    
}

inline char* lock_http2_client_nb::get_error_message(){ // returns the error message: the reason why a lock_http2_client instance's error flag is set
    
    return error_buffer;
    
}

inline bool lock_http2_client_nb::is_open(){

    return (client_state == OPEN) ? true : false;
    
}

bool lock_http2_client_nb::ping(){ // sends a ping on an established websocket connection
    
    if(!error){ // only continue if no error
        
    }
    
    return error;
    
}

inline bool lock_http2_client_nb::clear(){ // clear the error flag of a lock client in open state

    if(client_state == OPEN){
            
        memset(error_buffer, '\0', strlen(error_buffer));
            
        error = false;
            
    }
        
    return error;
    
}

bool lock_http2_client_nb::send(char* path, char* payload_data, int method, int id){ // sends data passed as parameter along an established http connection

    if(!error){ // only continue if no error
    
        // we check that the supplied method int is within the valid range - we return true to indicate that this send failed but we don't set the error flag to true
        if(method < 0 || method > std::size(methods) - 1) return true;

        // we update our method pseudo header with the supplied method
        update_header(const_cast<char*>(methods[method]), method_index);

        // we update our path pseudo header with the supplied path
        update_header(path, path_index);

        // our scheme and authority pseudo headers remain constant so we don't update it

        // we setup ad initialise our data provider
        nghttp2_data_provider2 provider;
        provider.source.ptr = const_cast<char*>(payload_data);
        provider.source.fd = (payload_data != nullptr) ? strlen(payload_data) : 0; // we store our payload data size
        provider.read_callback = send_body_provider_cb;

        // we fetch our next free data array we would use to store this stream's response
        int slot = acquire();

        // we check that we acquired a valid slot
        if(slot < 0){

            strcpy(error_buffer, "Error acquiring data slot for http request");

            error = true;

            return error;

        }

        // getting here we have acquired an initialised data slot we now store the user supplied id in our metadata slot
        metadata[slot].user_id = id;

        // we submit our request and fetch the stream_id - we pas our metadata slot as a void pointer to this request
        int32_t stream_id = nghttp2_submit_request2(session, nullptr, hdrs, num_of_headers, (payload_data != nullptr) ? &provider : nullptr, static_cast<void*>(&metadata[slot]));

        if(stream_id < 0){

            strcpy(error_buffer, "Failed to submit request to session context: ");

            // we concatenate the nghttp2 specific error
            strcat(error_buffer, nghttp2_strerror(stream_id));
        
            error = true;

        }

        // continue if on error
        if(!error){

            // we serialise and send out our request in this loop
            while(true){

                // this pointer we would pass to session mem send to store the location of the internal buffer holding the serialised bytes
                uint8_t* data_ptr = nullptr;

                // we call session mem send2 to serialise our data, this function calls our data provider callback which copies our supplied data to the ession's intrnal buffers
                ssize_t pending_bytes = nghttp2_session_mem_send2(session, const_cast<const uint8_t**>(&data_ptr));
                
                if(pending_bytes < 0){

                    strcpy(error_buffer, "nghttp2 engine serialization error: ");

                    // we concatenate the nghttp2 specific error
                    strcat(error_buffer, nghttp2_strerror(pending_bytes));
                
                    error = true;

                    break;
                        
                }
            
                if(pending_bytes == 0){

                    break; // no more frames left to build for this transmission block so we break out of our serialisation loop
                    
                }

                // block SIGPIPE signal before attempting to send data, just incase the connection is closed
                block_sigpipe_signal();
                
                int64_t len = 0;

                // keep polling till we have sent the entire frame
                while(len < pending_bytes){

                    int64_t local_len = BIO_write(c_bio, data_ptr, pending_bytes - len);

                    if(local_len > 0){

                        len += local_len;
                                
                        data_ptr += local_len;

                    }
                    else{

                        if(BIO_should_retry(c_bio)){

                            continue;

                        }
                        else{

                            // here wolfssl_read couldn't send any extra data
                            strcpy(error_buffer, "Write failure while transmitting outbound queue.");

                            error = true;
                            
                            unblock_sigpipe_signal();

                            // we return from this function
                            return error;
                            
                        }

                    }

                }

                // getting here the send request succeeds

                // we unblock the sigpipe signal
                unblock_sigpipe_signal();

            }

        }


    }
        
    return error;
    
}

inline int lock_http2_client_nb::default_receive(char* data_array, int length_of_array_data, int length_of_array){
    
    std::cout<<data_array<<std::endl;
    
    return 1;
    
}

inline int lock_http2_client_nb::default_pong_receive(char* data_array, int length_of_array_data, int length_of_array){
    
    std::cout<<data_array<<std::endl;
    
    return 1;
    
}

void lock_http2_client_nb::set_receive_function(lock_function fn){
    
    recv_data = std::move(fn);
    
}

void lock_http2_client_nb::set_pong_function(lock_function fn){
    
    recv_pong = std::move(fn);
    
}

bool lock_http2_client_nb::basic_read(){

    if(!error){ // only continue if no error
        
    }
        
    return error;
        
}
       
bool lock_http2_client_nb::connect(std::string_view url){ // this is used to connect to connect to the url passed as a parameter, it can be used when a lock client object was created without establishing a websocket connection by using the parameterless constructor, or to connect an already established websocket connection and lock client instance to a different websocket server, it can also be used to retry connecting an instance that encountered an error during connection
    
    if(client_state == CLOSED){
        
        memset(error_buffer, '\0', strlen(error_buffer)); // erase previous error message
        
        error = false;
        
    }
    else{ // the lock client instance has a websocket connection in open state
        
        memset(error_buffer, '\0', strlen(error_buffer)); // erase any previous error message
        
        error = false; // sets the error flag to false first so the close function can run 
        
        if(close()) // close the open websocket connection 
            
            error = false; // if the close function disconnects the connection because an unrecognised length was received, we need to set the error flag to 0 so that the rest of the connect function can proceed without hitch.
          
            // no need to memset since an unclean close sets the error flag but writes nothing to the error buffer
            
    }
  
    // check if url is a wss:// endpoint, check case insensitively
    
    if( (url.compare(0, 6, "wss://") == 0) || (url.compare(0, 6, "Wss://") == 0) || (url.compare(0, 6, "WSs://") == 0) || (url.compare(0, 6, "WSS://") == 0) || (url.compare(0, 6, "WsS://") == 0) || (url.compare(0, 6, "wSS://") == 0) || (url.compare(0, 6, "wsS://") == 0) || (url.compare(0, 6, "wSs://") == 0) ){ // endpoint is a wss:// endpoint, the second parameter to the std::string_view compare function is 6 which is the length of the string "wss://" which we are testing for the presence of, we list out and compare the 8 possible combinations of uppercase and lowercase lettering that are valid
    
        int protocol_prefix_len = strlen("wss://");

        // we fetch the url length without the wss:// prefix and any path appended to the url, we do this by finding the next '/' character after the initial wss://
        size_t base_url_end_index = url.find('/', protocol_prefix_len);

        int base_url_length = (base_url_end_index != std::string_view::npos) ? (int)base_url_end_index - protocol_prefix_len : url.size() - protocol_prefix_len; // saves the length of the url without the wss:// prefix and the path if any
        
        // size of required memory in bytes to store the base url and the port number if it would be appended
        int req_mem = base_url_length + 5; // we add an extra 5 bytes to the base url length to accomodate for the chance that this url was supplied without a port number so we have enough room to append port :443 to the base url

        // SSL members initialisations
        c_bio = BIO_new_ssl_connect(ssl_ctx); // creates a new bio ssl object
        BIO_get_ssl(c_bio, &c_ssl); // get the SSL structure component of the ssl bio for per instance SSL settings
        if(c_ssl == NULL){
            
            strncpy(error_buffer, "Error fetching SSL structure pointer ", error_buffer_array_length);
                    
            error = true;
            
        }
    
        if(!error){ // the constructor continues only if there was no error fetching the ssl pointer

            // URL copy 
            if(req_mem < url_static_array_length){ // static memory large enough
            
                url.copy(c_url_static, base_url_length, protocol_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the static character array
            
                c_url_static[base_url_length] = '\0'; // null-terminate the string
            
                c_url = c_url_static;
            
            }
            else if(req_mem < size_of_allocated_url_memory){ // store in already allocated dynamic memory
                
                url.copy(c_url_new, base_url_length, protocol_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the already allocated character array
            
                c_url_new[base_url_length] = '\0'; // null-terminate the string
            
                c_url = c_url_new;
                
            
            }
            else{ // neither static or dynamic memory is large enough, we test whether memory has already been allocated or not 
                
                if(c_url_new == NULL){ // memory has not yet been allocated
                    
                    c_url_new = new(std::nothrow) char[req_mem]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
                
                
                    if(c_url_new == NULL){
                        
                        strncpy(error_buffer, "Error allocating heap memory for lock_http2_client url parameter ", error_buffer_array_length);
                        
                        error = true;
                        
                    }
                    else{
                        
                        size_of_allocated_url_memory = req_mem;    
                            
                        url.copy(c_url_new, base_url_length, protocol_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
            
                        c_url_new[base_url_length] = '\0';
            
                        c_url = c_url_new;
                    
                    }
            
                }
                else{ // memory has been allocated but still isn't large enough
                    
                    delete [] c_url_new; // delete the already allocated memory
                    
                    // heap memory allocation for urls larger than the static array length
                    c_url_new = new(std::nothrow) char[req_mem]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
                
                    
                    if(c_url_new == NULL){
                        
                        strncpy(error_buffer, "Error allocating heap memory for lock_http2_client url parameter ", error_buffer_array_length);
                        
                        error = true;
                        
                    }
                    else{
                        
                        size_of_allocated_url_memory = req_mem;    
                            
                        url.copy(c_url_new, base_url_length, protocol_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
                
                        c_url_new[base_url_length] = '\0';

                        c_url = c_url_new;
                    
                    }
                
                }

            }
            
            if(!error){ // checks if there was any error allocating memory, that is if that part of the code was executed. The constructor only continues if there was no error 
                
                // we check if the supplied url has the port number appended if not we append it
                if(strchr(c_url, ':') == NULL){
                    strcat(c_url, ":443"); // we use strcat here because the array length check already checks that we have enough space in the array to accomodate for the port number
                }

                // set the websocket url(port included)
                BIO_set_conn_hostname(c_bio, c_url);
                
                // set SSL mode to retry automatically should SSL connection fail
                SSL_set_mode(c_ssl, SSL_MODE_AUTO_RETRY);
        
            }
        
        }
    
    }
    else{ // not a valid http endpoint
        
        strncpy(error_buffer, "Supplied URL parameter is not a valid HTTP endpoint", error_buffer_array_length);
                
        error = true;
        
    }
    // initialisation of BIO and SSL structures end
    
    if(!error){ // only continue if no error
        
        int search_start_index = 6; // we store the index where we would begin the host name search from, we start searching from after the wss:// protocol prefix

        // we search for the colon to indicate the start of the port number if any or the forward slash to indicate the start of the path if appended whichever comes first as that would indicate the end of the host name
        size_t host_name_end_index = url.find_first_of(":/", search_start_index); // we start searching at the search_start_index - index 6 to bypass the wss:// protocol prefix length
        
        int host_name_len = (host_name_end_index == std::string_view::npos) ? url.size() - search_start_index : (int)host_name_end_index - search_start_index;

        if( host_name_len < host_static_array_length ){ // static array is large enough
        
            url.copy(c_host_static, host_name_len, search_start_index);
        
            c_host_static[host_name_len] = '\0';
        
            c_host = c_host_static;
        
        }
        else if( host_name_len < size_of_allocated_host_memory){ // dynamic memory is large enough
            
            url.copy(c_host_new, host_name_len, search_start_index);
        
            c_host_new[host_name_len] = '\0';
        
            c_host = c_host_new;
            
        }
        else{ // neither static or already allocated memory is large enough, we test the two possible cases
            
            if(c_host_new == NULL){ // memory has not been allocated yet 
            
                c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
        
        
                if(c_host_new == NULL){
            
                    strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                
                    error = true;    
            
                }
                else{
                    
                    size_of_allocated_host_memory = host_name_len + 1;
                    
                    url.copy(c_host_new, host_name_len, search_start_index);
        
                    c_host_new[host_name_len] = '\0';
        
                    c_host = c_host_new;
        
                }
            
            }
            else{ // memory has been allocated but it still isn't sufficient
                
                delete [] c_host_new; // delete the previously allocated memory
                
                c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
        
        
                if(c_host_new == NULL){
            
                    strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                
                    error = true;    
            
                }
                else{
                    
                    size_of_allocated_host_memory = host_name_len + 1;
                    
                    url.copy(c_host_new, host_name_len, search_start_index);
        
                    c_host_new[host_name_len] = '\0';
        
                    c_host = c_host_new;

        
                }
            
            }
            
        }
        
        if(!error){ // only continue if no error
        
            // we set the host name we wish to connect to for server name identification(SNI) if the websocket address passed is a wss:// address. We test this by checking that the c_ssl pointer is non-null
            if(!(c_ssl == NULL)){
                
                if(!SSL_set_tlsext_host_name(c_ssl, c_host)){
                // we test the return value. SSL_set_tlsext_host_name returns 0 on error and 1 on success
                    
                    strncpy(error_buffer, "Error setting up Lock client for SNI TLS extension", error_buffer_array_length);
                        
                    error = true;
                
                } 
                
            }
            
            if(!error){
            // only continue if no error
            
                // we store the start index of the path from the supplied url - we search for the next forward slash after the last colon, that is the start of the path in the supplied url string view
                size_t path_start_index = url.find('/', search_start_index);
                
                // we check if a forward slash was found after the last colon, if none was we connect to the default root path else the forward slash till the end of the url string is the path
                std::string_view path = (path_start_index != std::string_view::npos) ? url.substr(path_start_index) : "/";

                // copy the channel path parameter into the channel path array
                int path_string_len = path.size();
                
                if(path_string_len < path_static_array_length){ // we can store the path in the static array if this condition is true
                    
                    path.copy(c_path_static, path_string_len); // copy the path into the static array
                    c_path_static[path_string_len] = '\0'; // null-terminate the array
                    
                    c_path = c_path_static;
                    
                }
                else if(path_string_len < size_of_allocated_path_memory){ // allocated memory is large enough
                    
                    path.copy(c_path_new, path_string_len); // copy the path into the allocated array
                    c_path_new[path_string_len] = '\0'; // null-terminate the array
                    
                    c_path = c_path_new;
                    
                }
                else{ // neither static or already allocated memory is large enough, we test the two possible cases 
                    
                    if(c_path_new == NULL){ //memory has not been allocated yet
                    
                        c_path_new = new(std::nothrow) char[path_string_len + 1]; // allocate memory for the path string with the std::nothrow parameter so C++ throws no exceptons even if memory allocation fails. We check for this below
                    
                        if(c_path_new == NULL){
                        
                            strncpy(error_buffer, "Error allocating heap memory for lock_http2_client channel path ", error_buffer_array_length);
                            
                            error = true;
                            
                        }
                        else{ 
                            
                            size_of_allocated_path_memory = path_string_len + 1;
                            
                            path.copy(c_path_new, path_string_len); // copy the path into the dynamically allocated array
                    
                            c_path_new[path_string_len] = '\0'; // null-terminate the array
                    
                            c_path = c_path_new;
                    
                        }
                        
                    }
                    else{ // memory has been allocated but is still not sufficient
                        
                        delete [] c_path_new; // delete already allocated memory
                        
                        c_path_new = new(std::nothrow) char[path_string_len + 1]; // allocate memory for the path string with the std::nothrow parameter so C++ throws no exceptons even if memory allocation fails. We check for this below
                    
                        if(c_path_new == NULL){
                        
                            strncpy(error_buffer, "Error allocating heap memory for lock_http2_client channel path ", error_buffer_array_length);
                            
                            error = true;
                            
                        }
                        else{ 
                            
                            size_of_allocated_path_memory = path_string_len + 1;
                            
                            path.copy(c_path_new, path_string_len); // copy the path into the dynamically allocated array
                    
                            c_path_new[path_string_len] = '\0'; // null-terminate the array
                    
                            c_path = c_path_new;
                    
                        }
                        
                    }
                    
                }
                
                if(!error){ // only continue if no error

                    // Set the BIO to non-blocking
                    BIO_set_nbio(c_bio, 1);

                    // make the connection
                    while(BIO_do_connect(c_bio) <= 0){
                        
                        if(BIO_should_retry(c_bio)){
                        // getting here the read request would block so we just return

                            continue;

                        }
                        else{
                            
                            strncpy(error_buffer, "Error connecting to WebSocket host ", error_buffer_array_length);
                        
                            error = true;

                            break;

                        }

                    }
                    
                    // upgrade the connection to websocket
                    if(!error){ // only continue if no error
                    
                    }
                
                }
    
            }
    
        }
    
    }

    return error;
        
}

bool lock_http2_client_nb::interface_connect(std::string_view url, in_addr* interface_address, char* interface_name){
    
    if(client_state == CLOSED){
        
        memset(error_buffer, '\0', strlen(error_buffer)); // erase previous error message
        
        error = false;
        
    }
    else{ // the lock client instance has a websocket connection in open state
        
        memset(error_buffer, '\0', strlen(error_buffer)); // erase any previous error message
        
        error = false; // sets the error flag to false first so the close function can run 
        
        if(close()) // close the open websocket connection 
            
            error = false; // if the close function disconnects the connection because an unrecognised length was received, we need to set the error flag to 0 so that the rest of the connect function can proceed without hitch.
          
            // no need to memset since an unclean close sets the error flag but writes nothing to the error buffer
            
    }

    // check if url is a ws:// or wss:// endpoint, check case insensitively

    if( (url.compare(0, 6, "wss://") == 0) || (url.compare(0, 6, "Wss://") == 0) || (url.compare(0, 6, "WSs://") == 0) || (url.compare(0, 6, "WSS://") == 0) || (url.compare(0, 6, "WsS://") == 0) || (url.compare(0, 6, "wSS://") == 0) || (url.compare(0, 6, "wsS://") == 0) || (url.compare(0, 6, "wSs://") == 0) ){ // endpoint is a wss:// endpoint, the second parameter to the std::string_view compare function is 6 which is the length of the string "wss://" which we are testing for the presence of, we list out and compare the 8 possible combinations of uppercase and lowercase lettering that are valid
    
        int protocol_prefix_len = strlen("wss://");

        // we fetch the url length without the wss:// prefix and any path appended to the url, we do this by finding the next '/' character after the initial wss://
        size_t base_url_end_index = url.find('/', protocol_prefix_len);

        int base_url_length = (base_url_end_index != std::string_view::npos) ? (int)base_url_end_index - protocol_prefix_len : url.size() - protocol_prefix_len; // saves the length of the url without the wss:// prefix and the path if any

        // size of required memory in bytes to store the base url and the port number if it would be appended
        int req_mem = base_url_length + 5; // we add an extra 5 bytes to the base url length to accomodate for the chance that this url was supplied without a port number so we have enough room to append port :443 to the base url
        
        // URL copy 
        if(req_mem < url_static_array_length){ // static memory large enough
        
            url.copy(c_url_static, base_url_length, protocol_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the static character array
        
            c_url_static[base_url_length] = '\0'; // null-terminate the string
        
            c_url = c_url_static;
        
        }
        else if(req_mem < size_of_allocated_url_memory){ // store in already allocated dynamic memory
        
            url.copy(c_url_new, base_url_length, protocol_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the already allocated character array
        
            c_url_new[base_url_length] = '\0'; // null-terminate the string
        
            c_url = c_url_new;
            
        
        }
        else{ // neither static or dynamic memory is large enough, we test whether memory has already been allocated or not
            
            if(c_url_new == NULL){ // memory has not yet been allocated
                
                c_url_new = new(std::nothrow) char[req_mem]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
                if(c_url_new == NULL){
                    
                    strncpy(error_buffer, "Error allocating heap memory for lock_http2_client url parameter ", error_buffer_array_length);
                    
                    error = true;
                    
                }
                else{
                    
                    size_of_allocated_url_memory = req_mem;    
                        
                    url.copy(c_url_new, base_url_length, protocol_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
        
                    c_url_new[base_url_length] = '\0';
        
                    c_url = c_url_new;
                
                }
        
            }
            else{ // memory has been allocated but still isn't large enough
                
                delete [] c_url_new; // delete the already allocated memory
                
                // heap memory allocation for urls larger than the static array length
                c_url_new = new(std::nothrow) char[req_mem]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
                
                if(c_url_new == NULL){
                    
                    strncpy(error_buffer, "Error allocating heap memory for lock_http2_client url parameter ", error_buffer_array_length);
                    
                    error = true;
                    
                }
                else{
                    
                    size_of_allocated_url_memory = req_mem;    
                        
                    url.copy(c_url_new, base_url_length, protocol_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
            
                    c_url_new[base_url_length] = '\0';

                    c_url = c_url_new;
                
                }
            
            }

        }

        if(!error){

            // we check if the supplied url has the port number appended if not we append it
            if(strchr(c_url, ':') == NULL){
                strcat(c_url, ":443"); // we use strcat here because the array length check already checks that we have enough space in the array to accomodate for the port number
            }

            // we search for the colon to indicate the start of the port number if any or the forward slash to indicate the start of the path if appended whichever comes first as that would indicate the end of the host name
            size_t host_name_end_index = url.find_first_of(":/", protocol_prefix_len); // we start searching at the protocol_prefix_len - index 6 to bypass the wss:// protocol prefix length
            
            int host_name_len = (host_name_end_index == std::string_view::npos) ? url.size() - protocol_prefix_len : (int)host_name_end_index - protocol_prefix_len;

            if( host_name_len < host_static_array_length ){ // static array is large enough
            
                url.copy(c_host_static, host_name_len, protocol_prefix_len);
            
                c_host_static[host_name_len] = '\0';
            
                c_host = c_host_static;
            
            }
            else if( host_name_len < size_of_allocated_host_memory){ // dynamic memory is large enough
                
                url.copy(c_host_new, host_name_len, protocol_prefix_len);
            
                c_host_new[host_name_len] = '\0';
            
                c_host = c_host_new;
                
            }
            else{ // neither static or already allocated memory is large enough, we test the two possible cases
                
                if(c_host_new == NULL){ // memory has not been allocated yet 
                
                    c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
            
                    if(c_host_new == NULL){
                
                        strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                    
                        error = true;    
                
                    }
                    else{
                        
                        size_of_allocated_host_memory = host_name_len + 1;
                        
                        url.copy(c_host_new, host_name_len, protocol_prefix_len);
            
                        c_host_new[host_name_len] = '\0';
            
                        c_host = c_host_new;
            
                    }
                
                }
                else{ // memory has been allocated but it still isn't sufficient
                    
                    delete [] c_host_new; // delete the previously allocated memory
                    
                    c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
            
                    if(c_host_new == NULL){
                
                        strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                    
                        error = true;    
                
                    }
                    else{
                        
                        size_of_allocated_host_memory = host_name_len + 1;
                        
                        url.copy(c_host_new, host_name_len, protocol_prefix_len);
            
                        c_host_new[host_name_len] = '\0';
            
                        c_host = c_host_new;

            
                    }
                
                }
                
            }

            // we create a local char array to hold the port extracted from the url
            const int MAX_CHAR_FOR_PORT = 8; // a port number can have a maximum of 5 characters because port numbers are 16 bit integers
            char c_port[MAX_CHAR_FOR_PORT];

            // since the host_name_end_index already finds the first character out of : and / after the host name we use it to finc the port number location if any

            // we first check if the host name end index was either std::string_view::npos or / in which case we know the host wasn't supplied so we store 443 as the host, but if the : character was found then the host was supplied so we just create a sub string view from after the : character to either the / starting the path if supplied, but if not supplied till std::string_view::npos - host_name_end_index - 1 which would be a very large number the copy takes the rest of the url string_view
            std::string_view port = (host_name_end_index == std::string_view::npos || url[host_name_end_index] == '/') ? "443" : url.substr(host_name_end_index + 1, url.find('/', host_name_end_index) - host_name_end_index - 1);

            // we now copy the derived port into char array
            int num_of_chars_copied = port.copy(c_port, port.size());

            // we null terminate the c_port array
            c_port[num_of_chars_copied] = '\0';

            // now we can call the connect to server function that would return the configured socket file descriptor
            int sock = connect_to_server(c_host, c_port, interface_address, interface_name);

            if(error == false){
            // only continue if no error

                // we create an SSL object for this lock client instance
                SSL *c_ssl = SSL_new(ssl_ctx);
                if(c_ssl == NULL){
                    
                    strncpy(error_buffer, "Error creating SSL structure ", error_buffer_array_length);
                    error = true;
                }
            
                if(!error){
                // continue if no error

                    // Set SNI
                    SSL_set_tlsext_host_name(c_ssl, c_host);

                    // set SSL mode to retry automatically should SSL connection fail
                    SSL_set_mode(c_ssl, SSL_MODE_AUTO_RETRY);

                    // Create BIO for this socket
                    BIO* sock_bio = BIO_new_socket(sock, BIO_NOCLOSE);
                    if (!sock_bio) {
                        SSL_free(c_ssl);
                        ::close(sock);
                        strncpy(error_buffer, "Error creating BIO structure from socket", error_buffer_array_length);          
                        error = true;
                    }

                    if(!error){
                    // continue if no error

                        // now we create an SSL BIO
                        BIO* ssl_bio = BIO_new(BIO_f_ssl());
                        BIO_set_ssl(ssl_bio, c_ssl, BIO_CLOSE);

                        // Chain ssl_bio and sock_bio together
                        c_bio = BIO_push(ssl_bio, sock_bio);

                        // Initialize SSL connection
                        SSL_set_connect_state(c_ssl);  // Set as client

                        // Perform handshake
                        if (BIO_do_handshake(c_bio) <= 0) {
                            std::cout << "SSL handshake failed"<< std::endl;
                            BIO_free_all(c_bio); // this throws segmentation fault when called without any network connection
                            strncpy(error_buffer, "SSL handshake failed", error_buffer_array_length);          
                            error = true;
                        }
                        else{
                            std::cout << "SSL handshake successful"<< std::endl;
                        }

                        // we fetch the path for this connection

                        if(!error){
                        // continue if no error

                            // we check if a forward slash was found after the last colon, if none was we connect to the default root path else the forward slash till the end of the url string is the path
                            std::string_view path = (base_url_end_index != std::string_view::npos) ? url.substr(base_url_end_index) : "/";

                            // copy the channel path parameter into the channel path array
                            int path_string_len = path.size();
                            
                            if(path_string_len < path_static_array_length){ // we can store the path in the static array if this condition is true
                                
                                path.copy(c_path_static, path_string_len); // copy the path into the static array
                                c_path_static[path_string_len] = '\0'; // null-terminate the array
                                
                                c_path = c_path_static;
                                
                            }
                            else if(path_string_len < size_of_allocated_path_memory){ // allocated memory is large enough
                                
                                path.copy(c_path_new, path_string_len); // copy the path into the allocated array
                                c_path_new[path_string_len] = '\0'; // null-terminate the array
                                
                                c_path = c_path_new;
                                
                            }
                            else{ // neither static or already allocated memory is large enough, we test the two possible cases 
                                
                                if(c_path_new == NULL){ //memory has not been allocated yet
                                
                                    c_path_new = new(std::nothrow) char[path_string_len + 1]; // allocate memory for the path string with the std::nothrow parameter so C++ throws no exceptons even if memory allocation fails. We check for this below
                                
                                    if(c_path_new == NULL){
                                    
                                        strncpy(error_buffer, "Error allocating heap memory for lock_http2_client channel path ", error_buffer_array_length);
                                        
                                        error = true;
                                        
                                    }
                                    else{ 
                                        
                                        size_of_allocated_path_memory = path_string_len + 1;
                                        
                                        path.copy(c_path_new, path_string_len); // copy the path into the dynamically allocated array
                                
                                        c_path_new[path_string_len] = '\0'; // null-terminate the array
                                
                                        c_path = c_path_new;
                                
                                    }
                                    
                                }
                                else{ // memory has been allocated but is still not sufficient
                                    
                                    delete [] c_path_new; // delete already allocated memory
                                    
                                    c_path_new = new(std::nothrow) char[path_string_len + 1]; // allocate memory for the path string with the std::nothrow parameter so C++ throws no exceptons even if memory allocation fails. We check for this below
                                
                                    if(c_path_new == NULL){
                                    
                                        strncpy(error_buffer, "Error allocating heap memory for lock_http2_client channel path ", error_buffer_array_length);
                                        
                                        error = true;
                                        
                                    }
                                    else{ 
                                        
                                        size_of_allocated_path_memory = path_string_len + 1;
                                        
                                        path.copy(c_path_new, path_string_len); // copy the path into the dynamically allocated array
                                
                                        c_path_new[path_string_len] = '\0'; // null-terminate the array
                                
                                        c_path = c_path_new;
                                
                                    }
                                    
                                }
                                
                            }
                            
                            if(!error){ // only continue if no error
                            
                            }
                        }
                    }
                }
            }
        }
    }
    else{ // not a valid http endpoint
        
        strncpy(error_buffer, "Supplied URL parameter is not a valid HTTP endpoint", error_buffer_array_length);
                
        error = true;
        
    }

    return error;
}

int lock_http2_client_nb::connect_to_server(const char *hostname, const char *port, in_addr* interface_address, const char *interface_name){

    struct addrinfo hints, *res = NULL, *p = NULL;

    // we create the socket the BIO structure would use
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cout<<"Error creating socket"<<std::endl;
        strncpy(error_buffer, "Error creating socket", error_buffer_array_length);          
        error = true;
        return -1;
    }

    // Bind to a specific device
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name)) < 0) {
        std::cout<<"Error binding socket to device"<<std::endl;
        perror("setsockopt(SO_BINDTODEVICE)");
        strncpy(error_buffer, "Error binding socket to device", error_buffer_array_length);          
        error = true;
        ::close(sock);
        return -1;
    }
    else{
        std::cout<<"Successfully bound socket to device "<<interface_name<<std::endl;
    }

    // Set up local address structure
    struct sockaddr_in localaddr;
    memset(&localaddr, 0, sizeof(localaddr));
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = interface_address->s_addr;
    localaddr.sin_port = 0;  // Lets the system choose port

    // Bind socket to specific interface
    if (bind(sock, (struct sockaddr*)&localaddr, sizeof(localaddr)) < 0) {
        // if the binding fails the library does not set the error flag to true it just prints the error message, ignores the specified interface and attempts to make the connection with whatever network interface is available
        std::cout<<"Lockws Error: Binding To Supplied Interface Address Failed...Connection Will Be Attempted With The Default Network Interface Address..."<<std::endl;
    }

    // Set up hints for getaddrinfo
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;      // IPv4 (use AF_UNSPEC for both IPv4 and IPv6)
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets

    // Perform DNS resolution
    if (getaddrinfo(hostname, port, &hints, &res) != 0) {
        std::cout<<"Error resolving hostname: "<<hostname<<std::endl;
        strncpy(error_buffer, "Error resolving hostname", error_buffer_array_length);          
        error = true;
        return -1;
    }

    // Iterate over results and try to connect
    for(p = res; p != NULL; p = p->ai_next) {

        // Try to connect
        if (::connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
            std::cout<<"Connected to "<<hostname<<std::endl;
            break; // Connected successfully
        }

        perror("connect");
        ::close(sock);
        sock = -1;
    }

    if(res != NULL)
        freeaddrinfo(res); // Free the addrinfo structure if non null

    if (sock < 0) {
        std::cout<<"Failed to connect to "<<hostname<<':'<<port<<std::endl;
        strncpy(error_buffer, "Failed to connect to host", error_buffer_array_length);          
        error = true;
        return -1;
    }

    // set the socket to non blocking mode
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    return sock; // Return the connected socket
}

void lock_http2_client_nb::block_sigpipe_signal(){

    sigemptyset(&newset);
    sigemptyset(&oldset);
    sigaddset(&newset, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &newset, &oldset);
    
}

void lock_http2_client_nb::unblock_sigpipe_signal(){

    // clear out any SIGPIPE signal that came in while we blocked it
    while(sigtimedwait(&newset, &si, &ts) >= 0 || errno != EAGAIN);
    
    // restore the previous signal mask of the calling thread
    pthread_sigmask(SIG_SETMASK, &oldset, NULL);
    
    
}
     
bool lock_http2_client_nb::close(){ // this closes an established websocket connection although the object itself still exists till it goes out of scope, the object can be connected to a different or the same websocket server using the connect function

    if(!error){ // only continue if no error
        
        
                
    }
    
    return error; // returning an error of 1 from the close function just means that the close was not a clean one but it was successful nonetheless, and the close function does not write any message to the error buffer
}

#pragma GCC diagnostic pop