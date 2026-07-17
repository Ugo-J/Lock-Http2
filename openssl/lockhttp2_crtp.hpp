#pragma once

#include "lockhttp2_headers.hpp"
#include "lockhttp2_structure_crtp.hpp"

// use the following pragma declaration to suppress the shift overflow warning
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshift-count-overflow"

// non blocking lock client function variants

// constructor with url string
template <typename T>
lock_http2_client_nb_crtp<T>::lock_http2_client_nb_crtp(std::string_view url){

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

                // set the https url(port included)
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
                        
                        strcpy(error_buffer, "Error connecting to https host ");
                    
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
template <typename T>
lock_http2_client_nb_crtp<T>::lock_http2_client_nb_crtp(std::string_view url, in_addr* interface_address, char* interface_name){

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
template <typename T>
lock_http2_client_nb_crtp<T>::lock_http2_client_nb_crtp(){
    
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

        // we set our http2 protocol headers so any user defined header can come after these protocol headers as required by the protocol

        // we set our method pseudo header with nullptr value, when connect is called this header's index is stored
        set_header(":method", nullptr);

        // we set our path pseudo header with, when connect is called this header's index is stored
        set_header(":path", nullptr);

        // we set our scheme pseudo header with nullptr, this value is updated after a connection is established
        set_header(":scheme", nullptr);

        // we set our authority pseudo header with nullptr, this value is updated when a connection is established
        set_header(":authority", nullptr);

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
template <typename T>
lock_http2_client_nb_crtp<T>::~lock_http2_client_nb_crtp(){
    
    // close the https connection if any
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

template <typename T>
int lock_http2_client_nb_crtp<T>::on_frame_recv_cb(nghttp2_session *session, const nghttp2_frame *frame, void *user_data){

    lock_http2_client_nb_crtp* client = static_cast<lock_http2_client_nb_crtp*>(user_data);
    return client->handle_frame_recv(frame);
}

template <typename T>
int lock_http2_client_nb_crtp<T>::on_data_chunk_recv_cb(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data){

    lock_http2_client_nb_crtp* client = static_cast<lock_http2_client_nb_crtp*>(user_data);
    return client->handle_data_chunk(flags, stream_id, data, len);

}

template <typename T>
int lock_http2_client_nb_crtp<T>::on_stream_close_cb(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data){

    lock_http2_client_nb_crtp* client = static_cast<lock_http2_client_nb_crtp*>(user_data);
    return client->handle_stream_close(stream_id, error_code);
}

template <typename T>
long lock_http2_client_nb_crtp<T>::send_body_provider_cb(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data){

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

template <typename T>
int lock_http2_client_nb_crtp<T>::on_header_cb(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data){

    lock_http2_client_nb_crtp* client = static_cast<lock_http2_client_nb_crtp*>(user_data);

    // we fetch our stream data for this request
    meta_data* stream_metadata = static_cast<meta_data*>(nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));

    return client->recv_header(reinterpret_cast<const char*>(name), namelen, reinterpret_cast<const char*>(value), valuelen, (stream_metadata != nullptr) ? stream_metadata->user_id : -1);

}

template <typename T>
int lock_http2_client_nb_crtp<T>::handle_frame_recv(const nghttp2_frame *frame){

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

template <typename T>
int lock_http2_client_nb_crtp<T>::recv_header(const char* name, size_t namelen, const char* value, size_t valuelen, int user_id){

    return static_cast<T*>(this)->recv_header(name, namelen, value, valuelen, user_id);

}

template <typename T>
int lock_http2_client_nb_crtp<T>::handle_data_chunk(uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len){

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

template <typename T>
int lock_http2_client_nb_crtp<T>::handle_stream_close(int32_t stream_id, uint32_t error_code){

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

template <typename T>
inline bool lock_http2_client_nb_crtp<T>::status(){ // returns the error status of a lock_http2_client instance
    
    return error;
    
}

template <typename T>
inline char* lock_http2_client_nb_crtp<T>::get_error_message(){ // returns the error message: the reason why a lock_http2_client instance's error flag is set
    
    return error_buffer;
    
}

template <typename T>
inline bool lock_http2_client_nb_crtp<T>::is_open(){

    return (client_state == OPEN) ? true : false;
    
}

template <typename T>
bool lock_http2_client_nb_crtp<T>::ping(){ // sends a ping on an established http connection
    
    if(!error){ // only continue if no error
        
        // we define our opaque payload which is just 8 bytes of 0s because http2 ping payload must be exactly 8 bytes long
        uint8_t opaque_payload[8] = {0};

        // now we submit the ping frame to the internal nghttp2 outbound queue
        int rv = nghttp2_submit_ping(session, NGHTTP2_FLAG_NONE, opaque_payload);

        // we check that there was no errors
        if(rv != 0){

            strcpy(error_buffer, "Failed to submit ping to session context: ");

            // we concatenate the nghttp2 specific error
            strcat(error_buffer, nghttp2_strerror(rv));
        
            error = true;

            return error;

        }

        // getting here the ping was submitted successfully to the nghttp2 session so now we send it

        // we serialise and send out our request in this loop
        while(true){

            // this pointer we would pass to session mem send to store the location of the internal buffer holding the serialised bytes
            uint8_t* data_ptr = nullptr;

            // we call session mem send2 to serialise our data
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
                        strcpy(error_buffer, "Write failure while transmitting outbound queue in ping request.");

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
    
    return error;
    
}

template <typename T>
inline bool lock_http2_client_nb_crtp<T>::clear(){ // clear the error flag of a lock client in open state

    if(client_state == OPEN){
            
        memset(error_buffer, '\0', strlen(error_buffer));
            
        error = false;
            
    }
        
    return error;
    
}

template <typename T>
bool lock_http2_client_nb_crtp<T>::send(char* path, char* payload_data, int method, int id){ // sends data passed as parameter along an established http connection

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

            return error;

        }

        // getting the the request was successfully submitted to the nghttp2 session so now we send it

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
        
    return error;
    
}

template <typename T>
inline int lock_http2_client_nb_crtp<T>::recv_data(char* data_array, int length_of_array_data, int length_of_array, int id){
    
    return static_cast<T*>(this)->recv_data(data_array, length_of_array_data, length_of_array, id);
    
}

template <typename T>
bool lock_http2_client_nb_crtp<T>::basic_read(){

    if(!error){ // only continue if no error
        
        // block SIGPIPE signal before attempting to read data, just incase the connection is closed
        block_sigpipe_signal();

        // we check if there is any available data to be read
        int len = BIO_read(c_bio, data_array, DATA_ARRAY_LENGTH);

        // if bio_read returns a value <= 0 we check if there is data available to be read
        if(len <= 0){

            // we check if the read error was caused by no data to read
            if(BIO_should_retry(c_bio)){

                // getting here no data is available to read so we unblock our sigpipe sigal and exit

                // we unblock the sigpipe signal
                unblock_sigpipe_signal();

                // we return error at this point because it is still 0 and it signals that basic read didn't fail there just is no data to read
                return error;


            }
            else{

                // here wolfssl_read couldn't fetch any data
                strcpy(error_buffer, "Read failure while polling inbound queue: ");

                // we concatenate the openssl error
                ERR_error_string(len, error_buffer + strlen(error_buffer));

                error = true;

                // we unblock the sigpipe signal
                unblock_sigpipe_signal();

                return error;

            }

        }

        // we read the raw TLS bytes and hand them over to the HTTP/2 engine. this call internally triggers our registered header/data callbacks with the corresponding data
        ssize_t processed_bytes = nghttp2_session_mem_recv2(session, reinterpret_cast<const uint8_t*>(data_array), (size_t)len);
        
        if(processed_bytes < 0){

            strcpy(error_buffer, "nghttp2 deserialization error: ");
            strcat(error_buffer, nghttp2_strerror(processed_bytes));
            error = true;

        }

        // we unblock the sigpipe signal
        unblock_sigpipe_signal();

    }
        
    return error;
        
}

template <typename T>
bool lock_http2_client_nb_crtp<T>::connect(std::string_view url){ // this is used to connect to connect to the url passed as a parameter, it can be used when a lock client object was created without establishing a https connection by using the parameterless constructor, or to connect an already established https connection and lock client instance to a different https server, it can also be used to retry connecting an instance that encountered an error during connection
    
    if(client_state == CLOSED){
        
        memset(error_buffer, '\0', strlen(error_buffer)); // erase previous error message
        
        error = false;
        
    }
    else{ // the lock client instance has a connection in open state
        
        memset(error_buffer, '\0', strlen(error_buffer)); // erase any previous error message
        
        error = false; // sets the error flag to false first so the close function can run 
        
        // we close the https connection
        close();
            
    }
  
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
            
            if(!error){ // checks if there was any error allocating memory, that is if that part of the code was executed. The constructor only continues if there was no error 
                
                // we append our port number - we use strcat here because the array length check already checks that we have enough space in the array to accomodate for the port number
                strcat(c_url, ":443");

                // set the https url(port included)
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
                        
                        strcpy(error_buffer, "Error connecting to https host ");
                    
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

                        // we first clear all previous headers
                        clear_all_headers();

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

    return error;
        
}

template <typename T>
bool lock_http2_client_nb_crtp<T>::interface_connect(std::string_view url, in_addr* interface_address, char* interface_name){
    
    if(client_state == CLOSED){
        
        memset(error_buffer, '\0', strlen(error_buffer)); // erase previous error message
        
        error = false;
        
    }
    else{ // the lock client instance has a connection in open state
        
        memset(error_buffer, '\0', strlen(error_buffer)); // erase any previous error message
        
        error = false; // sets the error flag to false first so the close function can run 
        
        // we close the https connection
        close();
            
    }

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
                
                        strcpy(error_buffer, "Error allocating heap memory for server host name ");
                    
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
                
                        strcpy(error_buffer, "Error allocating heap memory for server host name ");
                    
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

                                // we first clear all previous headers
                                clear_all_headers();

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

    return error;
}

template <typename T>
int lock_http2_client_nb_crtp<T>::connect_to_server(const char *hostname, const char *port, in_addr* interface_address, const char *interface_name){

    struct addrinfo hints, *res = NULL, *p = NULL;

    // we create the socket the BIO structure would use
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        std::cout<<"Error creating socket"<<std::endl;
        strcpy(error_buffer, "Error creating socket");          
        error = true;
        return -1;
    }

    // Bind to a specific device
    if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name)) < 0){
        std::cout<<"Error binding socket to device"<<std::endl;
        perror("setsockopt(SO_BINDTODEVICE)");
        strcpy(error_buffer, "Error binding socket to device");          
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
    if(getaddrinfo(hostname, port, &hints, &res) != 0) {
        std::cout<<"Error resolving hostname: "<<hostname<<std::endl;
        strcpy(error_buffer, "Error resolving hostname");          
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

    if(sock < 0){
        std::cout<<"Failed to connect to "<<hostname<<':'<<port<<std::endl;
        strcpy(error_buffer, "Failed to connect to host");          
        error = true;
        return -1;
    }

    // set the socket to non blocking mode
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    // now we return the connected socket
    return sock;
}

template <typename T>
int lock_http2_client_nb_crtp<T>::acquire(){

    // the builtin ctz function is undefined when passed a parameter of 0 so we check that the static mask isn't 0

    if(static_mask != 0){

        // we fetch the lowest free bit in our bit mask
        int slot = __builtin_ctz(static_mask);

        // we mark the acquired slot as in use
        static_mask &= ~(1u << slot);

        // we set up the metadata slot we just acquired

        // we first check if this memort location has been initialised before
        if(metadata[slot].data_array == nullptr){

            // getting here this location hasn't been initialised before so we initialise it

            // we set the data array pointer
            metadata[slot].data_array = static_array[slot];

            // we set the cursor
            metadata[slot].cursor = static_array[slot];

            // we set the array size
            metadata[slot].array_size = STATIC_ARRAY_SIZE;

            // we set the array index both in the metadata array and the data array array because these are two parallel arrays
            metadata[slot].array_index = slot;

        }
        else{

            // getting here this location has been initialised before so we just reset our cursor
            metadata[slot].cursor = static_array[slot];

        }

        return slot;

    }

    // getting here the static array was full so we check the heap array

    // the builtin ctz function is undefined when passed a parameter of 0 so we check that the heap mask isn't 0

    if(heap_mask != 0){

        // we fetch the lowest free bit in our bit mask
        int slot = __builtin_ctzll(heap_mask);

        // we mark the acquired slot as in use
        heap_mask &= ~(1ull << slot);

        // we add NUM_OF_STATIC_ARRAYS to our acquired slot because heap mask metadata entries start at index NUM_OF_STATIC_ARRAYS
        slot += NUM_OF_STATIC_ARRAYS;

        // we initialise our slot location

        // we check if memory has been allocated in this metadata location before
        if(metadata[slot].data_array == nullptr){

            // getting here memory has not been allocated to this location before so we allocate it

            // we allocate memory for our data array pointer - we size the allocated memory just like our static array arrays
            metadata[slot].data_array = new(std::nothrow) char[STATIC_ARRAY_SIZE]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail

            // we check that data was indeed allocated ad return if the allocation fails
            if(metadata[slot].data_array == nullptr) return -1;

            // we set the cursor
            metadata[slot].cursor = metadata[slot].data_array;

            // we set the array size
            metadata[slot].array_size = STATIC_ARRAY_SIZE;

            // we set the array index both in the metadata array and the data array array becasue these are two parallel arrays
            metadata[slot].array_index = slot;

        }
        else{

            // getting here memory has been allocated before for this location so we just reset its cursor other variables remain valid
            metadata[slot].cursor = metadata[slot].data_array;

        }

        return slot;

    }

    return -1;

}

template <typename T>
int lock_http2_client_nb_crtp<T>::acquire_heap(int sz){

    // we first check that we have a free heap slot
    if(heap_mask == 0) return -1;

    // we get a local copy of our heap mask
    uint64_t free_slots = heap_mask;

    while(free_slots != 0){

        // we fetch our next free heap slot
        int bit_index = __builtin_ctzll(free_slots);
        int slot = bit_index + NUM_OF_STATIC_ARRAYS;

        // we check if memory has already been allocated for this slot
        if(metadata[slot].data_array == nullptr){

            // getting here memory has not been allocated for this slot so we allocate its required memory, initialise its data members and return this slot

            // we allocate memory for our data array pointer - we use the supplied parameter as the heap array size
            metadata[slot].data_array = new(std::nothrow) char[sz]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail

            // we check that data was indeed allocated ad return if the allocation fails
            if(metadata[slot].data_array == nullptr) return -1;

            // we set the cursor
            metadata[slot].cursor = metadata[slot].data_array;

            // we set the array size
            metadata[slot].array_size = sz;

            // we set the array index both in the metadata array and the data array array becasue these are two parallel arrays
            metadata[slot].array_index = slot;

            // we mark this slot as in use
            heap_mask &= ~(1ull << bit_index);

            // we return this slot
            return slot;

        }

        // getting here memory has already been allocated for this slot so we check if the allocated memory for this slot is >= our acquire heap parameter
        if(metadata[slot].array_size >= sz){

            // getting here this array size ia >= our sz parameter so we reset our cursor mark this slot as in use and return it

            // we reset the cursor
            metadata[slot].cursor = metadata[slot].data_array;

            // we mark this slot as in use
            heap_mask &= ~(1ull << (slot - NUM_OF_STATIC_ARRAYS));

            // we return this slot
            return slot;

        }

        free_slots &= ~(1ull << bit_index);

    }

    // getting here there is no free slot with size >= sz and no empty slot we can use so we return -1
    return -1;

}

template <typename T>
void lock_http2_client_nb_crtp<T>::release(int slot){

    // we first check if the slot to release is a static slot or a heap slot
    if(slot < NUM_OF_STATIC_ARRAYS){

        static_mask |= (1u << slot);
    }
    else{

        heap_mask |= (1ull << (slot - NUM_OF_STATIC_ARRAYS));
    }

}

template <typename T>
int lock_http2_client_nb_crtp<T>::set_header(const char* name, char* value){

    // we check if the name parameter is null if it is we return immediately - the value parameter on the other hand permits a null value - a null value parameter just creates the header entry and returns the int index the application can pass to update header to update the header in place
    if(name == nullptr) return -1;

    // we get the length of the header name
    int name_len = strlen(name);

    // we get the length of the header value
    int value_len = (value != nullptr) ? strlen(value) : 0;

    // we first check that our header name length is not longer than our header name array length
    if(name_len > MAX_HEADER_ITEM_LENGTH - 1) return -1;

    // array for holding our lower case name
    char lowercase_name[MAX_HEADER_ITEM_LENGTH];

    // we use a lambda to convert our name parameter to lower case
    [](char* out, const char* in){ while((*out++ = tolower(*in++))); }(lowercase_name, name);

    // we first check if this header exists already on our headers array, if it does we just update its value
    for(int i = 0; i<num_of_headers; i++){

        // we compare the headers based on name length first
        if(hdrs[i].namelen == static_cast<size_t>(name_len)){

            // now we compare the characters using memcmp - h_name[i] is the char array whose pointer is sored in hdrs[i].name so we compare the name directly
            if(!memcmp(lowercase_name, h_name[i], name_len)){

                // we check if the supplied value was not null before we copy the value
                if(value != nullptr){

                    // we check if the header would fit into our header value location - we compare directly to avoid the use of strncpy
                    if(value_len > MAX_HEADER_ITEM_LENGTH - 1) return -1;

                    // we copy this value into our headers array
                    strcpy(h_value[i], value);

                    // we update our nghttp2 header value pointer back to this header value location just in case we have used update header to update its value pointer
                    hdrs[i].value = reinterpret_cast<uint8_t*>(h_value[i]);

                    // our namelen size remains the same so we only update our valuelen size
                    hdrs[i].valuelen = static_cast<size_t>(value_len);

                    // our nghttp2 header flags remain no copy for name and value so we leave as is

                }

                // we return the index to this header value in the h_value array
                return i;

                // we don't increment our num of headers because this header was already present in our headers array

            }

        }

    }

    // getting here this header isn't already in our headers array so before we enter it we first check if there is enough header space
    if(num_of_headers >= MAX_NUM_OF_HEADERS) return -1;

    // getting here we still have empty slots in our headers array

    // we don't check the header name length again as we already checked it before converting it to lower case at the start of this function

    // we copy our header name
    strcpy(h_name[num_of_headers], lowercase_name);

    // we point our nghttp2 hdrs name pointer to our header name
    hdrs[num_of_headers].name = reinterpret_cast<uint8_t*>(h_name[num_of_headers]);

    // we update our namelen variable in our nghttp2 header struct
    hdrs[num_of_headers].namelen = static_cast<size_t>(name_len);

    // we only copy our value to our h value array if the supplied value is not null
    if(value != nullptr){

        // we copy our header value - we first check that our header value length is not longer than our header value array length
        if(value_len > MAX_HEADER_ITEM_LENGTH - 1) return -1;

        // we copy our header value
        strcpy(h_value[num_of_headers], value);

    }

    // we point our nghttp2 hdrs value pointer to our header value
    hdrs[num_of_headers].value = reinterpret_cast<uint8_t*>(h_value[num_of_headers]);

    // we update our valuelen variable in our nghttp2 header struct
    hdrs[num_of_headers].valuelen = static_cast<size_t>(value_len);

    // we set our nghttp2 hdrs flag to no copy to ensure that the headers are not copied internally
    hdrs[num_of_headers].flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE;

    // we return our header index and increment our num of headers in the same line
    return num_of_headers++;

}

template <typename T>
char* lock_http2_client_nb_crtp<T>::get_header(char* name){

    // we check if the supplied name is a nullptr, if so we return immediately
    if(name == nullptr) return nullptr;

    // we get the length of the header name
    int name_len = strlen(name);

    // we first check that our header name length is not longer than our header name array length
    if(name_len > MAX_HEADER_ITEM_LENGTH - 1) return nullptr;

    // array for holding our lower case name
    char lowercase_name[MAX_HEADER_ITEM_LENGTH];

    // we use a lambda to convert our name parameter to lower case
    [](char* out, const char* in){ while((*out++ = tolower(*in++))); }(lowercase_name, name);

    // we check for this header in our headers array
    for(int i = 0; i<num_of_headers; i++){

        // we compare the headers based on name length first
        if(hdrs[i].namelen == static_cast<size_t>(name_len)){

            // now we compare the characters using memcmp - h_name[i] is the char array whose pointer is sored in hdrs[i].name so we compare the name directly
            if(!memcmp(lowercase_name, h_name[i], name_len)){

                // we return the header value pointer of this header
                return reinterpret_cast<char*>(hdrs[i].value);

            }

        }

    }

    // getting here this header was not found in our headers array so we return
    return nullptr;

}

template <typename T>
char* lock_http2_client_nb_crtp<T>::get_header_ptr(int index){

    // return nullptr if the supplied index is invalid or empty - this prevents us from updating a header value for a header we are not actively sending with our requests
    if(index < 0 || index >= num_of_headers) return nullptr;

    // we return the internal header pointer
    return h_value[index];

}

template <typename T>
int lock_http2_client_nb_crtp<T>::update_header_length(int index, int length){

    // return nullptr if the supplied index is invalid or empty - this prevents us from updating a header value for a header we are not actively sending with our requests
    if(index < 0 || index >= num_of_headers) return -1;

    // we update our hdrs value length or compute it from the corresponding h_value if it is not supplied
    hdrs[index].valuelen = (length >= 0) ? static_cast<size_t>(length) : strlen(h_value[index]);

    // we point our nghttp hdrs value for this index to our h_value index just incase the value pointer has been reassigned by calling update_header
    hdrs[index].value = reinterpret_cast<uint8_t*>(h_value[index]);

    return 0;

}

template <typename T>
char* lock_http2_client_nb_crtp<T>::update_header(char* value, int index){

    // return nullptr if the supplied value is null
    if(value == nullptr) return nullptr;

    // return nullptr if the supplied index is invalid or empty
    if(index < 0 || index >= num_of_headers) return nullptr;

    // we update the nghttp2 value pointer for this header to the supplied value
    hdrs[index].value = reinterpret_cast<uint8_t*>(value);

    // we update the valuelen for this header
    hdrs[index].valuelen = static_cast<size_t>(strlen(value));

    // we return the value pointer to indicate success
    return value;

}

template <typename T>
int lock_http2_client_nb_crtp<T>::clear_header(int index){

    // this function clears a single header from the header list

    // we check if the supplied index is valid and non empty
    if(index < 0 || index >= num_of_headers) return -1;

    int last_index = num_of_headers - 1;

    // we check if this is the last header in our header array or not
    if(index < last_index){

        // getting here this isn't the last header so we move the headers after this forward by copying the last entries

        // we copy the last header name into this location
        strcpy(h_name[index], h_name[last_index]);

        // we copy the last header value to this index location
        strcpy(h_value[index], h_value[last_index]);

        // we update our hdrs array
        hdrs[index] = hdrs[last_index];

        // we reassign the name pointer of our hdrs entry to point to its new name location
        hdrs[index].name = reinterpret_cast<uint8_t*>(h_name[index]);

        // now we check the hdrs value pointer, we only reassign it if it is pointing to its corresponding location in the h_value array, if it is pointing to an external array by virtue of calling update header on it we don't bother updating it because the location it points to would still be valid for its context
        if(hdrs[index].value == reinterpret_cast<uint8_t*>(h_value[last_index])) hdrs[index].value = reinterpret_cast<uint8_t*>(h_value[index]);

    }

    // we decrement our num_of_headers
    num_of_headers--;

    return 0;

}

template <typename T>
int lock_http2_client_nb_crtp<T>::clear_headers(){

    // this function clears all user supplied headers leaving only the pseudo headers, to do this we just set our num of headers to 4 which is the 4 pseudo headers we use: path, method, scheme and authority
    num_of_headers = 4;

    return 0;

}

template <typename T>
int lock_http2_client_nb_crtp<T>::clear_all_headers(){

    // this is an internal function that clears all headers including pseudo headers by setting our num of headers to 0
    num_of_headers = 0;

    return 0;

}

template <typename T>
void lock_http2_client_nb_crtp<T>::block_sigpipe_signal(){

    sigemptyset(&newset);
    sigemptyset(&oldset);
    sigaddset(&newset, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &newset, &oldset);
    
}

template <typename T>
void lock_http2_client_nb_crtp<T>::unblock_sigpipe_signal(){

    // clear out any SIGPIPE signal that came in while we blocked it
    while(sigtimedwait(&newset, &si, &ts) >= 0 || errno != EAGAIN);
    
    // restore the previous signal mask of the calling thread
    pthread_sigmask(SIG_SETMASK, &oldset, NULL);
    
    
}

template <typename T>
bool lock_http2_client_nb_crtp<T>::close(){ // this closes an established https connection although the object itself still exists till it goes out of scope, the object can be connected to a different or the same https server using the connect function

    if(!error){ // only continue if no error
        
        // we call bio reset on our bio
        BIO_reset(c_bio);

        // we set our client state to closed
        client_state = CLOSED;
                
    }
    
    return error; // returning an error of 1 from the close function just means that the close was not a clean one but it was successful nonetheless, and the close function does not write any message to the error buffer
}

#pragma GCC diagnostic pop