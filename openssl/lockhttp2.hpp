#pragma once

#include "lockhttp2_headers.hpp"
#include "lockhttp2_structure.hpp"

// use the following pragma declaration to suppress the shift overflow warning
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshift-count-overflow"

// non blocking lock client function variants

// constructor with url string
lock_http2_client_nb::lock_http2_client_nb(std::string_view url){

    // initialisation of class wide variables
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    
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

}

// constructor that binds to a network interface
lock_http2_client_nb::lock_http2_client_nb(std::string_view url, in_addr* interface_address, char* interface_name){

    // initialise our ssl ctx
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    
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

}

// parameterless constructor
lock_http2_client_nb::lock_http2_client_nb(){
    
    // initialise ssl ctx
    SSL_CTX_new(TLS_client_method());

    // we set the application layer protocol for our ssl ctx to http2
    SSL_CTX_set_alpn_protos(ssl_ctx, (const unsigned char *)"\x02h2", 3);
    
}

// destructor
lock_http2_client_nb::~lock_http2_client_nb(){
    
    // close the websocket connection if any
    if(client_state == OPEN){
        
        close();
        
    }
    
    // free url heap memory - this only runs if dynamic memory allocation is used to store the url
    if(!(c_url_new == NULL)){
        
        delete [] c_url_new;
        
    }
    
    // free path heap memory if the path string was stored in dynamic memory
    if(!(c_path_new == NULL)){
        
        delete [] c_path_new;
        
    }
    
    // free host heap memory if host string was stored in dynamic memory
    if(!(c_host_new == NULL)){
        
        delete [] c_host_new;
        
    }
    
    // free upgrade request string heap memory if upgrade request string was stored in dynamic memory
    if(!(upgrade_request_new == NULL)){
        
        delete [] upgrade_request_new;
        
    }
    
    if(c_ssl != NULL && c_url != NULL){// this would mean that the object is an ssl bio
        
        BIO_free_all(c_bio); // frees the ssl bio chain
    }
    
    if(send_data_new != NULL){
        
        delete [] send_data_new; // free the memory used if the send string is stored on the heap
        
    }
    
    if (data_array_new != NULL){
        
        delete [] data_array_new; // free the memory used to receive data
        
    }
    
}

inline bool lock_http2_client_nb::status(){ // returns the error status of a lock_http2_client instance
    
    return error;
    
}

inline char* lock_http2_client_nb::get_error_message(){ // returns the error message: the reason why a lock_http2_client instance's error flag is set
    
    return error_buffer;
    
}

inline bool lock_http2_client_nb::is_open(){

    if(client_state == OPEN)
        return true;
    else
        return false;
    
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

bool lock_http2_client_nb::send(std::string_view payload_data){ // sends data passed as parameter along an established websocket connection

    if(!error){ // only continue if no error
        
        if(client_state == OPEN){ // only continue if client is in open state
        
            uint64_t payload_data_len = payload_data.size();
            int i = 0; // variable for traversing the send data array
            
            if( (payload_data_len + biggest_header_len) < send_data_array_len ){ // static array is large enough
                
                send_data = (char*)send_data_static;
                
                // set the first byte
                send_data[i] = (unsigned char)(FIN_BIT_SET | RSV_BIT_UNSET_ALL | TEXT_FRAME);
                i++;
                
                // set the second byte
                if(payload_data_len < 126){ // if payload data length is less than 126 the next 7 bits represent the payload length
                    
                    send_data[i] = MASK_BIT_SET | (unsigned char)payload_data_len;
                    i++;
                    
                }
                else if( (payload_data_len > 125) && (payload_data_len < MAX_2BYTE_INT) ){ // next byte stores the value 126 and the next two bytes store the payload length
                    
                    send_data[i] = (unsigned char)(MASK_BIT_SET | (unsigned char)126);
                    i++;
                    
                    send_data[i] = (0xFF00 & payload_data_len) >> 8;
                    i++;
                    
                    send_data[i] = 0x00FF & payload_data_len;
                    i++;
                    
                }
                else if( (payload_data_len > (MAX_2BYTE_INT - 1)) && (payload_data_len < (MAX_8BYTE_INT - 1)) ){
                    // next byte stores the value 127 and he next 8 bytes store the payload length
                    
                    send_data[i] = (unsigned char)(MASK_BIT_SET | (unsigned char)127);
                    i++;
                    
                    send_data[i] = (0xFF00000000000000 & payload_data_len) >> 56 ; // the most significant bit cannot be 1 since we have the MAX_8BYTE_INT range test before executing this part of the code
                    i++;
                    
                    send_data[i] = (0x00FF000000000000 & payload_data_len) >> 48;
                    i++;
                    
                    send_data[i] = (0x0000FF0000000000 & payload_data_len) >> 40;
                    i++;
                    
                    send_data[i] = (0x000000FF00000000 & payload_data_len) >> 32;
                    i++;
                    
                    send_data[i] = (0x00000000FF000000 & payload_data_len) >> 24;
                    i++;
                    
                    send_data[i] = (0x0000000000FF0000 & payload_data_len) >> 16;
                    i++;
                    
                    send_data[i] = (0x000000000000FF00 & payload_data_len) >> 8;
                    i++;
                    
                    send_data[i] = (0x00000000000000FF & payload_data_len); // no shift required
                    i++;
                    
                    
                }
                else{ // ERROR!! Data length too large - execution never gets here normally because the static send data array is only a few kilobytes long and the payload data would have to be > 2^64 bytes in length to get here which would already fail the outer if statement for being > static send data array, the code is just added for completeness
                    
                    strncpy(error_buffer, "Send data length too large", error_buffer_array_length);
                    
                    error = true;
                    
                }

                if(!error){ // only continue if no error
                    
                    for(int j = 0; j<mask_array_len; j++){
                        
                        send_data[i] = mask[j]; // store the mask in the send data array
                        
                        i++;
                        
                    }
                    // mask storing end 
                    
                    // mask the data and store the masked data in the send data array 
                    int k = 0; // variable used to store the mask index of the exact byte in the mask array to mask with
                    
                    for(int j = 0; j<payload_data_len; j++){
                        
                        k = j % 4;
                        
                        send_data[i] = payload_data[j] ^ mask[k];
                        
                        i++;
                        
                    }
                    
                    // block SIGPIPE signal before attempting to send data, just incase the connection is closed
                    block_sigpipe_signal();
                    
                    // send the data
                    int64_t len = 0;

                    // keep polling till we have sent the entire frame
                    while(len < i){

                        int64_t local_len = BIO_write(c_bio, send_data, i - len);

                        if(local_len > 0){

                            len += local_len;
                                    
                            send_data += local_len;

                        }
                        else{
                            if(BIO_should_retry(c_bio)){
                            
                                continue;

                            }
                            else{

                                // here bio_read couldn't fetch any extra data
                                strncpy(error_buffer, "Websocket Connection Lost", error_buffer_array_length);

                                error = true;
                                
                                // we unblock the sigpipe signal because fail_ws_connection internally blocks it
                                unblock_sigpipe_signal();

                                fail_ws_connection(GOING_AWAY);
                                
                                // the connection getting lost isn't in itself an error it just puts the lock client in a closed state

                                return error;

                            }
                        }

                    }

                    // getting here the send request succeeds

                    // we unblock the sigpipe signal
                    unblock_sigpipe_signal();
                
                }
                  
            }
            else{
            // here the payload data is larger than the size of the send data array so we send the data out with multiple frames

                send_data = (char*)send_data_static;
                
                // set the first byte stating that this is a multiframe data payload
                send_data[i] = FIN_BIT_NOT_SET | RSV_BIT_UNSET_ALL | TEXT_FRAME;
                i++;

                // we store the frame length of the frame - we set the frame length of the individual frames to send_data_array_len - biggest_header_len so the frame can be fit into the static array irrespective of the websocket header length
                uint64_t frame_data_len = send_data_array_len - biggest_header_len;

                // this variable holds the index of the payload data that the sending continues from after each frame
                uint64_t continuation_index = 0;
                
                // set the second byte
                if(frame_data_len < 126){ // if frame data length is less than 126 the next 7 bits represent the frame length
                    
                    send_data[i] = MASK_BIT_SET | (unsigned char)frame_data_len;
                    i++;
                    
                }
                else if( (frame_data_len > 125) && (frame_data_len < MAX_2BYTE_INT) ){ // next byte stores the value 126 and the next two bytes store the payload length
                    
                    send_data[i] = (unsigned char)(MASK_BIT_SET | (unsigned char)126);
                    i++;
                    
                    send_data[i] = (0xFF00 & frame_data_len) >> 8;
                    i++;
                    
                    send_data[i] = (0x00FF & frame_data_len);
                    i++;
                    
                }
                else if( (frame_data_len > (MAX_2BYTE_INT - 1)) && (frame_data_len < (MAX_8BYTE_INT - 1)) ){
                // next byte stores the value 127 and he next 8 bytes store the payload length
                    
                    send_data[i] = (unsigned char)(MASK_BIT_SET | (unsigned char)127);
                    i++;
                    
                    send_data[i] = (0xFF00000000000000 & frame_data_len) >> 56 ; // the most significant bit cannot be 1 since we have the MAX_8BYTE_INT range test before executing this part of the code
                    i++;
                    
                    send_data[i] = (0x00FF000000000000 & frame_data_len) >> 48;
                    i++;
                    
                    send_data[i] = (0x0000FF0000000000 & frame_data_len) >> 40;
                    i++;
                    
                    send_data[i] = (0x000000FF00000000 & frame_data_len) >> 32;
                    i++;
                    
                    send_data[i] = (0x00000000FF000000 & frame_data_len) >> 24;
                    i++;
                    
                    send_data[i] = (0x0000000000FF0000 & frame_data_len) >> 16;
                    i++;
                    
                    send_data[i] = (0x000000000000FF00 & frame_data_len) >> 8;
                    i++;
                    
                    send_data[i] = (0x00000000000000FF & frame_data_len); // no shift required
                    i++;
                    
                    
                }
                
                for(int j = 0; j<mask_array_len; j++){
                    
                    send_data[i] = mask[j]; // store the mask in the send data array
                    
                    i++;
                    
                }
                // mask storing end 
                
                // mask the data and store the masked data in the send data array 
                int k = 0; // variable used to store the mask index of the exact byte in the mask array to mask with
                
                for(uint64_t j = 0; j<frame_data_len; j++){

                    k = j % 4;
                    
                    send_data[i] = payload_data[j] ^ mask[k];
                    
                    i++;
                    
                }

                // increment the continuation index by frame data len
                continuation_index += frame_data_len;

                // block SIGPIPE signal before attempting to send data, just incase the connection is closed
                block_sigpipe_signal();
                
                int64_t len = 0;

                // keep polling till we have sent the entire frame
                while(len < i){

                    int64_t local_len = BIO_write(c_bio, send_data, i - len);

                    if(local_len > 0){

                        len += local_len;
                                
                        send_data += local_len;

                    }
                    else{
                        if(BIO_should_retry(c_bio)){
                        
                            continue;

                        }
                        else{

                            // here bio_read couldn't fetch any extra data
                            strncpy(error_buffer, "Websocket Connection Lost", error_buffer_array_length);

                            error = true;
                            
                            // we unblock the sigpipe signal because fail_ws_connection internally blocks it
                            unblock_sigpipe_signal();

                            fail_ws_connection(GOING_AWAY);
                            
                            // the connection getting lost isn't in itself an error it just puts the lock client in a closed state

                            return error;

                        }
                    }

                }

                // getting here the send request for this frame succeeds

                // we unblock the sigpipe signal
                unblock_sigpipe_signal();

                // we now build up the continuation frames

                // we loop till the continuation index equals the payload data len
                while(continuation_index < payload_data_len){

                    // we test if the unsent portion of the data can be sent out as a single frame now
                    if(payload_data_len - continuation_index <= send_data_array_len - biggest_header_len){
                    // we send out this frame with the fin bit set

                        // we set our iterator i back to 0
                        i = 0;

                        // we set our frame data len to payload_data_len - continution index as that would be the length of the remaining data to be sent
                        frame_data_len = payload_data_len - continuation_index;
                        
                        // set the first byte
                        send_data[i] = (unsigned char)(FIN_BIT_SET | RSV_BIT_UNSET_ALL | CONTINUATION_FRAME);
                        i++;

                        // set the second byte
                        if(frame_data_len < 126){ // if payload data length is less than 126 the next 7 bits represent the payload length
                            
                            send_data[i] = MASK_BIT_SET | (unsigned char)frame_data_len;
                            i++;
                            
                        }
                        else if( (frame_data_len > 125) && (frame_data_len < MAX_2BYTE_INT) ){ // next byte stores the value 126 and the next two bytes store the payload length
                            
                            send_data[i] = (unsigned char)(MASK_BIT_SET | (unsigned char)126);
                            i++;
                            
                            send_data[i] = (0xFF00 & frame_data_len) >> 8;
                            i++;
                            
                            send_data[i] = (0x00FF & frame_data_len);
                            i++;
                            
                        }
                        else if( (frame_data_len > (MAX_2BYTE_INT - 1)) && (frame_data_len < (MAX_8BYTE_INT - 1)) ){
                        // next byte stores the value 127 and he next 8 bytes store the payload length
                            
                            send_data[i] = (unsigned char)(MASK_BIT_SET | (unsigned char)127);
                            i++;
                            
                            send_data[i] = (0xFF00000000000000 & frame_data_len) >> 56 ; // the most significant bit cannot be 1 since we have the MAX_8BYTE_INT range test before executing this part of the code
                            i++;
                            
                            send_data[i] = (0x00FF000000000000 & frame_data_len) >> 48;
                            i++;
                            
                            send_data[i] = (0x0000FF0000000000 & frame_data_len) >> 40;
                            i++;
                            
                            send_data[i] = (0x000000FF00000000 & frame_data_len) >> 32;
                            i++;
                            
                            send_data[i] = (0x00000000FF000000 & frame_data_len) >> 24;
                            i++;
                            
                            send_data[i] = (0x0000000000FF0000 & frame_data_len) >> 16;
                            i++;
                            
                            send_data[i] = (0x000000000000FF00 & frame_data_len) >> 8;
                            i++;
                            
                            send_data[i] = (0x00000000000000FF & frame_data_len); // no shift required
                            i++;
                            
                            
                        }
            
                        // we reuse the already generated mask to save computation
                        for(int j = 0; j<mask_array_len; j++){
                            
                            send_data[i] = mask[j]; // store the mask in the send data array
                            
                            i++;
                            
                        }

                        // mask the data and store the masked data in the send data array 
                        k = 0; // we reuse the variable used to store the mask index of the exact byte in the mask array to mask with
                        
                        // since this is the last frame we use continuation_index < payload_data_len as the conditional for this for loop
                        for(uint64_t j = continuation_index; j<payload_data_len; j++){

                            send_data[i] = payload_data[j] ^ mask[k];

                            k = ++k % 4;
                            
                            i++;
                            
                        }

                        // block SIGPIPE signal before attempting to send data, just incase the connection is closed
                        block_sigpipe_signal();
                        
                        int64_t len = 0;

                        // keep polling till we have sent the entire frame
                        while(len < i){

                            int64_t local_len = BIO_write(c_bio, send_data, i - len);

                            if(local_len > 0){

                                len += local_len;
                                        
                                send_data += local_len;

                            }
                            else{
                                if(BIO_should_retry(c_bio)){
                                
                                    continue;

                                }
                                else{

                                    // here bio_read couldn't fetch any extra data
                                    strncpy(error_buffer, "Websocket Connection Lost", error_buffer_array_length);

                                    error = true;
                                    
                                    // we unblock the sigpipe signal because fail_ws_connection internally blocks it
                                    unblock_sigpipe_signal();

                                    fail_ws_connection(GOING_AWAY);
                                    
                                    // the connection getting lost isn't in itself an error it just puts the lock client in a closed state

                                    return error;

                                }
                            }

                        }

                        // getting here the pong request send succeeds

                        // we unblock the sigpipe signal
                        unblock_sigpipe_signal();

                    }
                    else{
                    // we send out this frame with the fin bit not set - we do not alter the frame data len in this case as it would still be set to send_data_array_len - biggest_header_len

                        // we set our iterator i back to 0
                        i = 0;
                        
                        // we get our copy boundary index where our frame data for this frame stops
                        uint64_t copy_bound = continuation_index + frame_data_len;

                        // set the first byte
                        send_data[i] = FIN_BIT_NOT_SET | RSV_BIT_UNSET_ALL | CONTINUATION_FRAME;
                        i++;

                        // set the second byte
                        if(frame_data_len < 126){ // if payload data length is less than 126 the next 7 bits represent the payload length
                            
                            send_data[i] = MASK_BIT_SET | (unsigned char)frame_data_len;
                            i++;
                            
                        }
                        else if( (frame_data_len > 125) && (frame_data_len < MAX_2BYTE_INT) ){ // next byte stores the value 126 and the next two bytes store the payload length
                            
                            send_data[i] = (unsigned char)(MASK_BIT_SET | (unsigned char)126);
                            i++;
                            
                            send_data[i] = (0xFF00 & frame_data_len) >> 8;
                            i++;
                            
                            send_data[i] = (0x00FF & frame_data_len);
                            i++;
                            
                        }
                        else if( (frame_data_len > (MAX_2BYTE_INT - 1)) && (frame_data_len < (MAX_8BYTE_INT - 1)) ){
                        // next byte stores the value 127 and he next 8 bytes store the payload length
                            
                            send_data[i] = (unsigned char)(MASK_BIT_SET | (unsigned char)127);
                            i++;
                            
                            send_data[i] = (0xFF00000000000000 & frame_data_len) >> 56 ; // the most significant bit cannot be 1 since we have the MAX_8BYTE_INT range test before executing this part of the code
                            i++;
                            
                            send_data[i] = (0x00FF000000000000 & frame_data_len) >> 48;
                            i++;
                            
                            send_data[i] = (0x0000FF0000000000 & frame_data_len) >> 40;
                            i++;
                            
                            send_data[i] = (0x000000FF00000000 & frame_data_len) >> 32;
                            i++;
                            
                            send_data[i] = (0x00000000FF000000 & frame_data_len) >> 24;
                            i++;
                            
                            send_data[i] = (0x0000000000FF0000 & frame_data_len) >> 16;
                            i++;
                            
                            send_data[i] = (0x000000000000FF00 & frame_data_len) >> 8;
                            i++;
                            
                            send_data[i] = (0x00000000000000FF & frame_data_len); // no shift required
                            i++;
                            
                            
                        }
            
                        // we reuse the already generated mask to save computation
                        for(int j = 0; j<mask_array_len; j++){
                            
                            send_data[i] = mask[j]; // store the mask in the send data array
                            
                            i++;
                            
                        }

                        // mask the data and store the masked data in the send data array 
                        k = 0; // we reuse the variable used to store the mask index of the exact byte in the mask array to mask with
                        
                        for(uint64_t j = continuation_index; j<copy_bound; j++){

                            send_data[i] = payload_data[j] ^ mask[k];

                            k = ++k % 4;
                            
                            i++;
                            
                        }

                        // block SIGPIPE signal before attempting to send data, just incase the connection is closed
                        block_sigpipe_signal();
                        
                        int64_t len = 0;

                        // keep polling till we have sent the entire frame
                        while(len < i){

                            int64_t local_len = BIO_write(c_bio, send_data, i - len);

                            if(local_len > 0){

                                len += local_len;
                                        
                                send_data += local_len;

                            }
                            else{
                                if(BIO_should_retry(c_bio)){
                                
                                    continue;

                                }
                                else{

                                    // here bio_read couldn't fetch any extra data
                                    strncpy(error_buffer, "Websocket Connection Lost", error_buffer_array_length);

                                    error = true;
                                    
                                    // we unblock the sigpipe signal because fail_ws_connection internally blocks it
                                    unblock_sigpipe_signal();

                                    fail_ws_connection(GOING_AWAY);
                                    
                                    // the connection getting lost isn't in itself an error it just puts the lock client in a closed state

                                    return error;

                                }
                            }

                        }

                        // getting here the send request succeeds

                        // we unblock the sigpipe signal
                        unblock_sigpipe_signal();

                    }

                    // increment the continuation index by frame data len
                    continuation_index += frame_data_len;

                }

            }   

        }
        else{ // lock client in closed state
            
            strncpy(error_buffer, "Lock Client not connected", error_buffer_array_length);
            
            error = true;
            
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