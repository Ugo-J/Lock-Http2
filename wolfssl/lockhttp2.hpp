#pragma once

#include "lockhttp2_headers.hpp"
#include "lockhttp2_structure.hpp"

// use the following pragma declaration to suppress the shift overflow warning
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshift-count-overflow"


// non blocking lock client function variants

// constructor with url string
lock_http2_client_nb::lock_http2_client_nb(std::string_view url){

    if(wolfSSL_Init() != WOLFSSL_SUCCESS){

        strncpy(error_buffer, "Failed to initialize wolfSSL core runtime.", error_buffer_array_length);
            
        error = true;

    }

    if(!error){

        // we initialise our ssl ctx
        ssl_ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());

        if(!ssl_ctx){

            strncpy(error_buffer, "Context creation failed.", error_buffer_array_length);
                
            error = true;

        }

        // we load our system certificates
        int ca_ret = wolfSSL_CTX_load_system_CA_certs(ssl_ctx);

        if(ca_ret != WOLFSSL_SUCCESS){

            strncpy(error_buffer, "Failed to load system CA bundle.", error_buffer_array_length);

            error = true;
        }

        // now we set aside our static memory for our wolfssl ctx to use for io operations for ssl objects - we set the max number of session objects drawing from this pool to 1 in our last parameter
        wolfSSL_CTX_load_static_memory(&ssl_ctx, NULL, crypto_memory_pool, CRYPTO_ARENA_SIZE, WOLFMEM_IO_POOL, 1);

        // load the general memory pool
        wolfSSL_CTX_load_static_memory(&ssl_ctx, NULL, general_memory_pool, CRYPTO_ARENA_SIZE, WOLFMEM_GENERAL, 1);

    }

    if(!error){
    
        // check if url is a wss:// endpoint, check case insensitively - for thw wolfssl client we only implement the wss client
        
        if( (url.compare(0, 6, "wss://") == 0) || (url.compare(0, 6, "Wss://") == 0) || (url.compare(0, 6, "WSs://") == 0) || (url.compare(0, 6, "WSS://") == 0) || (url.compare(0, 6, "WsS://") == 0) || (url.compare(0, 6, "wSS://") == 0) || (url.compare(0, 6, "wsS://") == 0) || (url.compare(0, 6, "wSs://") == 0) ){ // endpoint is a wss:// endpoint, the second parameter to the std::string_view compare function is 6 which is the length of the string "wss://" which we are testing for the presence of, we list out and compare the 8 possible combinations of uppercase and lowercase lettering that are valid
        
            int protocol_prefix_len = strlen("wss://");

            // we fetch the url length without the wss:// prefix and any path appended to the url, we do this by finding the next '/' character after the initial wss://
            size_t base_url_end_index = url.find('/', protocol_prefix_len);

            int base_url_length = (base_url_end_index != std::string_view::npos) ? (int)base_url_end_index - protocol_prefix_len : url.size() - protocol_prefix_len; // saves the length of the url without the wss:// prefix and the path if any
            
            // size of required memory in bytes to store the base url and the port number if it would be appended
            int req_mem = base_url_length + 5; // we add an extra 5 bytes to the base url length to accomodate for the chance that this url was supplied without a port number so we have enough room to append port :443 to the base url

            // we create our ssl object
            c_ssl = wolfSSL_new(ssl_ctx);
        
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

                    // set SSL mode to retry automatically should SSL connection fail
                    // wolfSSL_set_mode(c_ssl, WOLFSSL_MODE_AUTO_RETRY);
            
                }
            
            }
        
        }
        else{ // not a valid/supported http endpoint
            
            strncpy(error_buffer, "Supplied URL parameter is not a valid/supported HTTP endpoint", error_buffer_array_length);
                    
            error = true;
            
        }
        
        if(!error){ // only continue if no error
            
            int search_start_index = 6; // we store the index where we would begin the host name search from, we start searching from after the wss:// protocol prefix

            // we search for the colon to indicate the start of the port number if any or the forward slash to indicate the start of the path if appended whichever comes first as that would indicate the end of the host name
            size_t host_name_end_index = url.find_first_of(":/", search_start_index); // we start searching at the search_start_index - index 6 to bypass the wss:// protocol prefix length
            
            int host_name_len = (host_name_end_index == std::string_view::npos) ? url.size() - search_start_index : (int)host_name_end_index - search_start_index;

            if(host_name_len < host_static_array_length){ // static array is large enough
            
                url.copy(c_host_static, host_name_len, search_start_index);
            
                c_host_static[host_name_len] = '\0';
            
                c_host = c_host_static;
            
            }
            else if(host_name_len < size_of_allocated_host_memory){ // dynamic memory is large enough
                
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
            
                // we set the host name we wish to connect to for server name identification(SNI) if the http address passed is a wss:// address. We test this by checking that the c_ssl pointer is non-null
                if(!(c_ssl == NULL)){
                    
                    if(!wolfSSL_UseSNI(c_ssl, WOLFSSL_SNI_HOST_NAME, c_host, host_name_len)){
                    // we test the return value. wolfSSL_UseSNI returns 0 on error and 1 on success
                        
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

                        // we create a local char array to hold the port extracted from the url
                        const int MAX_CHAR_FOR_PORT = 8; // a port number can have a maximum of 5 characters because port numbers are 16 bit integers
                        char c_port[MAX_CHAR_FOR_PORT];

                        // since the host_name_end_index already finds the first character out of : and / after the host name we use it to find the port number location if any

                        // we first check if the host name end index was either std::string_view::npos or / in which case we know the host wasn't supplied so we store 443 as the host, but if the : character was found then the host was supplied so we just create a sub string view from after the : character to either the / starting the path if supplied, but if not supplied till std::string_view::npos - host_name_end_index - 1 which would be a very large number the copy takes the rest of the url string_view
                        std::string_view port = (host_name_end_index == std::string_view::npos || url[host_name_end_index] == '/') ? "443" : url.substr(host_name_end_index + 1, url.find('/', host_name_end_index) - host_name_end_index - 1);

                        // we now copy the derived port into char array
                        int num_of_chars_copied = port.copy(c_port, port.size());

                        // we null terminate the c_port array
                        c_port[num_of_chars_copied] = '\0';

                        // we call our connect to server function with the interface parameters set to null
                        int sockfd = connect_to_server(c_host, c_port, nullptr, nullptr);
                        
                        if(!error){ // only continue if no error

                            // getting here the connect to server function returned successfully so now we bind the returned socket fd to our c_ssl object
                            wolfSSL_set_fd(c_ssl, sockfd);

                            // we set the application layer protocol for our ssl object to http2
                            wolfSSL_UseALPN(c_ssl, (char*)"h2", 2, WOLFSSL_ALPN_FAILED_ON_MISMATCH);

                            // we perform our tls handshake - since this is a non blocking socket we loop till our handshake is complete
                            int len;

                            while((len = wolfSSL_connect(c_ssl)) != WOLFSSL_SUCCESS){
                                
                                // we get the error message
                                int err = wolfSSL_get_error(c_ssl, len);

                                // we check if the wolfssl handle is still expecting a read or a write
                                if(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE){

                                    continue;

                                }
                                else{

                                    // getting here we got a actual error so we set our error flag
                                    strncpy(error_buffer, "Error performing tls handshake ", error_buffer_array_length);
                                
                                    error = true;

                                    // we break out of this loop
                                    break;

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

}

// constructor that binds to a network interface
lock_http2_client_nb::lock_http2_client_nb(std::string_view url, in_addr* interface_address, char* interface_name){

    if(wolfSSL_Init() != WOLFSSL_SUCCESS){

        strncpy(error_buffer, "Failed to initialize wolfSSL core runtime.", error_buffer_array_length);
            
        error = true;

    }

    if(!error){

        // we initialise our ssl ctx
        ssl_ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());

        if(!ssl_ctx){

            strncpy(error_buffer, "Context creation failed.", error_buffer_array_length);
                
            error = true;

        }

        // we load our system certificates
        int ca_ret = wolfSSL_CTX_load_system_CA_certs(ssl_ctx);

        if(ca_ret != WOLFSSL_SUCCESS){

            strncpy(error_buffer, "Failed to load system CA bundle.", error_buffer_array_length);

            error = true;
        }

        // now we set aside our static memory for our wolfssl ctx to use for io operations for ssl objects - we set the max number of session objects drawing from this pool to 1 in our last parameter
        wolfSSL_CTX_load_static_memory(&ssl_ctx, NULL, crypto_memory_pool, CRYPTO_ARENA_SIZE, WOLFMEM_IO_POOL, 1);

        // load the general memory pool
        wolfSSL_CTX_load_static_memory(&ssl_ctx, NULL, general_memory_pool, CRYPTO_ARENA_SIZE, WOLFMEM_GENERAL, 1);

    }
    
    if(!error){

        // check if url is a wss:// endpoint, check case insensitively

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

                // since the host_name_end_index already finds the first character out of : and / after the host name we use it to find the port number location if any

                // we first check if the host name end index was either std::string_view::npos or / in which case we know the host wasn't supplied so we store 443 as the host, but if the : character was found then the host was supplied so we just create a sub string view from after the : character to either the / starting the path if supplied, but if not supplied till std::string_view::npos - host_name_end_index - 1 which would be a very large number the copy takes the rest of the url string_view
                std::string_view port = (host_name_end_index == std::string_view::npos || url[host_name_end_index] == '/') ? "443" : url.substr(host_name_end_index + 1, url.find('/', host_name_end_index) - host_name_end_index - 1);

                // we now copy the derived port into char array
                int num_of_chars_copied = port.copy(c_port, port.size());

                // we null terminate the c_port array
                c_port[num_of_chars_copied] = '\0';

                // now we can call the connect to server function that would return the configured socket file descriptor
                int sockfd = connect_to_server(c_host, c_port, interface_address, interface_name);

                if(!error){ // only continue if no error

                    // getting here the connect to server function returned successfully so now we bind the returned socket fd to our c_ssl object
                    wolfSSL_set_fd(c_ssl, sockfd);

                    // we set the application layer protocol for our ssl object to http2
                    wolfSSL_UseALPN(c_ssl, (char*)"h2", 2, WOLFSSL_ALPN_FAILED_ON_MISMATCH);

                    // we perform our tls handshake - since this is a non blocking socket we loop till our handshake is complete
                    int len;

                    while((len = wolfSSL_connect(c_ssl)) != WOLFSSL_SUCCESS){
                        
                        // we get the error message
                        int err = wolfSSL_get_error(c_ssl, len);

                        // we check if the wolfssl handle is still expecting a read or a write
                        if(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE){

                            continue;

                        }
                        else{

                            // getting here we got a actual error so we set our error flag
                            strncpy(error_buffer, "Error performing tls handshake ", error_buffer_array_length);
                        
                            error = true;

                            // we break out of this loop
                            break;

                        }

                    }
                
                    if(!error){ // only continue if no error
                
                        // we fetch the path for this connection

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
                                
                                    strncpy(error_buffer, "Error allocating heap memory for lock_client channel path ", error_buffer_array_length);
                                    
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
                                
                                    strncpy(error_buffer, "Error allocating heap memory for lock_client channel path ", error_buffer_array_length);
                                    
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

                    }
                
                }
            }
        }
        else{ // not a valid/supported http endpoint
            
            strncpy(error_buffer, "Supplied URL parameter is not a valid/supported HTTP endpoint", error_buffer_array_length);
                    
            error = true;
            
        }

    }

}

// parameterless constructor
lock_http2_client_nb::lock_http2_client_nb(){
    
    if(wolfSSL_Init() != WOLFSSL_SUCCESS){

        strncpy(error_buffer, "Failed to initialize wolfSSL core runtime.", error_buffer_array_length);
            
        error = true;

    }

    if(!error){

        // we initialise our ssl ctx
        ssl_ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());

        if(!ssl_ctx){

            strncpy(error_buffer, "Context creation failed.", error_buffer_array_length);
                
            error = true;

        }

        // we load our system certificates
        int ca_ret = wolfSSL_CTX_load_system_CA_certs(ssl_ctx);

        if(ca_ret != WOLFSSL_SUCCESS){

            strncpy(error_buffer, "Failed to load system CA bundle.", error_buffer_array_length);

            error = true;
        }

        // now we set aside our static memory for our wolfssl ctx to use for io operations for ssl objects - we set the max number of session objects drawing from this pool to 1 in our last parameter
        // wolfSSL_CTX_load_static_memory(&ssl_ctx, NULL, crypto_memory_pool, CRYPTO_ARENA_SIZE, WOLFMEM_IO_POOL, 1);

        // load the general memory pool
        // wolfSSL_CTX_load_static_memory(&ssl_ctx, NULL, general_memory_pool, CRYPTO_ARENA_SIZE, WOLFMEM_GENERAL, 1);

        // NGHTTP2 INITIALISATION

        // continue if no error
        if(!error){

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

    }
    
}

// destructor
lock_http2_client_nb::~lock_http2_client_nb(){
    
    // close the http connection if any
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
    
    if(c_ssl != NULL && c_url != NULL){
        
        wolfSSL_free(c_ssl); // frees the wolfssl object
    }
    
    if(send_data_new != NULL){
        
        delete [] send_data_new; // free the memory used if the send string is stored on the heap
        
    }
    
    if (data_array_new != NULL){
        
        delete [] data_array_new; // free the memory used to receive data
        
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
    return client->handle_header(frame, name, namelen, value, valuelen, flags);

}

int lock_http2_client_nb::handle_frame_recv(const nghttp2_frame *frame){

    // we retrieve the custom id we attached during submit
    void* stream_data = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

    // we cast our stream data id to a uintptr_t so we can safely convert it to an int
    uintptr_t custom_id = reinterpret_cast<uintptr_t>(stream_data);
        
    // we cast our custom id to a int to get the int id supplied during the sed call for this request
    int user_req_id = static_cast<int>(custom_id);

    // we use this switch case to handle different header types
    switch(frame->hd.type){

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

    }

    return 0;
}

int lock_http2_client_nb::handle_header(const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags){

    if(frame->hd.type == NGHTTP2_HEADERS){

        std::string_view key(reinterpret_cast<const char*>(name), namelen);
        std::string_view val(reinterpret_cast<const char*>(value), valuelen);
        
        std::cout<<"[Stream "<<frame->hd.stream_id<<"] Header -> "<<key<<": "<<val<<"\n";
        
    }

    return 0;

}

int lock_http2_client_nb::handle_data_chunk(uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len){

    std::string_view chunk(reinterpret_cast<const char*>(data), len);
    
    std::cout<<"[Stream "<<stream_id<<"] Received "<<len<<" bytes of data.\n";

    // we use the session cnsume function to tell the engine we consumed these bytes so it can update the stream-level flow control window. Here, nghttp2_session_consume IS required.
    int rv = nghttp2_session_consume(session, stream_id, len);
    if(rv != 0 && rv != NGHTTP2_ERR_INVALID_ARGUMENT){

        // we ignore INVALID_ARGUMENT because control frames (like SETTINGS/PING) don't belong to a specific stream ID and shouldn't be consumed against it.
        strcpy(error_buffer, "Failed to update inbound stream window status.");
        error = true;

    }
    
    return 0;

}

int lock_http2_client_nb::handle_stream_close(int32_t stream_id, uint32_t error_code){

    if(error_code == NGHTTP2_NO_ERROR){

        std::cout<<"[Stream "<<stream_id<<"] Closed successfully.\n";

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

    if(client_state == OPEN) return true;
    else return false;
    
}

bool lock_http2_client_nb::ping(){ // sends a ping on an established http connection
    
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

bool lock_http2_client_nb::send(std::string_view path, char* payload_data, int method, int id){ // sends data passed as parameter along an established http connection

    if(!error){ // only continue if no error
    
        // we check that the supplied method int is within the valid range - we return true to indicate that this send failed but we don't set the error flag to true
        if(method < 0 || method > std::size(methods) - 1) return true;

        // we construct our http headers
        nghttp2_nv hdrs[] = {
        { (uint8_t*)":method", (uint8_t*)methods[method], 7, strlen(methods[method]), NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)":scheme", (uint8_t*)"https", 7, 5, NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)":path", (uint8_t*)path.data(), 5, path.size(), NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)":authority", (uint8_t*)c_host, 10, strlen(c_host), NGHTTP2_NV_FLAG_NONE }
        };

        // we setup ad initialise our data provider
        nghttp2_data_provider2 provider;
        provider.source.ptr = const_cast<char*>(payload_data);
        provider.source.fd = (payload_data != nullptr) ? strlen(payload_data) : 0; // we store our payload data size
        provider.read_callback = send_body_provider_cb;

        // we use a casting to uintptr_t to convert our supplied integer to a void pointer
        void* pv_id = reinterpret_cast<void*>(static_cast<uintptr_t>(id));

        // we submit our request and fetch the stream_id
        int32_t stream_id = nghttp2_submit_request2(session, nullptr, hdrs, std::size(hdrs), (payload_data != nullptr) ? &provider : nullptr, pv_id);

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

                    int64_t local_len = wolfSSL_write(c_ssl, data_ptr, pending_bytes - len);

                    if(local_len > 0){

                        len += local_len;
                                
                        data_ptr += local_len;

                    }
                    else{

                        // we get the error message
                        int err = wolfSSL_get_error(c_ssl, local_len);

                        if(err == WOLFSSL_ERROR_WANT_WRITE || err == WOLFSSL_ERROR_WANT_READ){

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
    
inline int lock_http2_client_nb::default_receive(char* data_array, int length_of_array_data, int length_of_array, int id){
    
    std::cout<<data_array<<std::endl;
    
    return 1;
    
}

void lock_http2_client_nb::set_receive_function(lock_function fn){
    
    recv_data = std::move(fn);
    
}

bool lock_http2_client_nb::basic_read(){

    if(!error){ // only continue if no error
        
        // block SIGPIPE signal before attempting to read data, just incase the connection is closed
        block_sigpipe_signal();

        // we check if there is any available data to be read
        int len = wolfSSL_read(c_ssl, data_array, static_data_array_length);

        // if wolfssl_read returns a value <= 0 we check if there is data available to be read
        if(len <= 0){

            std::cout<<len<<std::endl;

            // we get the error message
            int err = wolfSSL_get_error(c_ssl, len);

            std::cout<<err<<std::endl;

            // we check if the wolfssl library still expects more reads or if this is an actual error
            if(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE){

                // getting here no data is available to read so we unblock our sigpipe sigal and exit

                // we unblock the sigpipe signal
                unblock_sigpipe_signal();

                // we return error at this point because it is still 0 and it signals that basic read didn't fail there just is no data to read
                return error;


            }
            else if(err == WOLFSSL_ERROR_ZERO_RETURN){

                // getting here the remote host closed the connection
                strcpy(error_buffer, "Remote host closed connection: ");

                // we concatenate the wolfssl error
                wolfSSL_ERR_error_string(err, error_buffer + strlen(error_buffer));

                error = true;

                // we unblock the sigpipe signal
                unblock_sigpipe_signal();

                return error;

            }
            else{

                // here wolfssl_read couldn't fetch any data
                strcpy(error_buffer, "Read failure while polling inbound queue: ");

                // we concatenate the wolfssl error
                wc_ErrorString(err, error_buffer + strlen(error_buffer));

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
       
bool lock_http2_client_nb::connect(std::string_view url){ // this is used to connect to connect to the url passed as a parameter, it can be used when a lock client object was created without establishing a http connection by using the parameterless constructor, or to connect an already established http connection and lock client instance to a different http server, it can also be used to retry connecting an instance that encountered an error during connection
    
    if(client_state == CLOSED){
        
        memset(error_buffer, '\0', strlen(error_buffer)); // erase previous error message
        
        error = false;
        
    }
    else{ // the lock client instance has a http connection in open state
        
        memset(error_buffer, '\0', strlen(error_buffer)); // erase any previous error message
        
        error = false; // sets the error flag to false first so the close function can run 
        
        if(close()) // close the open http connection 
            
            error = false; // if the close function disconnects the connection because an unrecognised length was received, we need to set the error flag to 0 so that the rest of the connect function can proceed without hitch.
          
            // no need to memset since an unclean close sets the error flag but writes nothing to the error buffer
            
    }
  
    // check if url is a https:// endpoint, check case insensitively - for thw wolfssl client we only implement the wss client
        
    if(url.compare(0, 8, "https://") == 0){
    
        int protocol_prefix_len = strlen("https://");

        int base_url_length = url.size() - protocol_prefix_len; // saves the length of the url without the https:// prefix
        
        // size of required memory in bytes to store the base url
        int req_mem = base_url_length;

        // we create our ssl object
        c_ssl = wolfSSL_new(ssl_ctx);
    
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
            
            /* if(!error){ // checks if there was any error allocating memory, that is if that part of the code was executed. The constructor only continues if there was no error
                
                // we check if the supplied url has the port number appended if not we append it
                if(strchr(c_url, ':') == NULL){
                    strcat(c_url, ":443"); // we use strcat here because the array length check already checks that we have enough space in the array to accomodate for the port number
                }

                // set SSL mode to retry automatically should SSL connection fail
                // wolfSSL_set_mode(c_ssl, WOLFSSL_MODE_AUTO_RETRY);
        
            } */
        
        }
    
    }
    else{ // not a valid/supported http endpoint
        
        strncpy(error_buffer, "Supplied URL parameter is not a valid/supported HTTP endpoint", error_buffer_array_length);
                
        error = true;
        
    }
    
    if(!error){ // only continue if no error
        
        int search_start_index = 8; // we store the index where we would begin the host name search from, we start searching from after the https:// protocol prefix

        /* // we search for the colon to indicate the start of the port number if any or the forward slash to indicate the start of the path if appended whichever comes first as that would indicate the end of the host name
        size_t host_name_end_index = url.find_first_of(":/", search_start_index); // we start searching at the search_start_index - index 8 to bypass the https:// protocol prefix length */
        
        int host_name_len = url.size() - search_start_index;

        if(host_name_len < host_static_array_length){ // static array is large enough
        
            url.copy(c_host_static, host_name_len, search_start_index);
        
            c_host_static[host_name_len] = '\0';
        
            c_host = c_host_static;
        
        }
        else if(host_name_len < size_of_allocated_host_memory){ // dynamic memory is large enough
            
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
        
            // we set the host name we wish to connect to for server name identification(SNI) if the http address passed is a wss:// address. We test this by checking that the c_ssl pointer is non-null
            if(!(c_ssl == NULL)){
                
                if(!wolfSSL_UseSNI(c_ssl, WOLFSSL_SNI_HOST_NAME, c_host, host_name_len)){
                // we test the return value. wolfSSL_UseSNI returns 0 on error and 1 on success
                    
                    strcpy(error_buffer, "Error setting up Lock client for SNI TLS extension");
                        
                    error = true;
                
                }
                
            }
            
            if(!error){
            // only continue if no error

                // we create a local char array to hold the port extracted from the url
                const int MAX_CHAR_FOR_PORT = 8; // a port number can have a maximum of 5 characters because port numbers are 16 bit integers
                char c_port[MAX_CHAR_FOR_PORT];

                // we set our port number to 443 as this is a https request
                std::string_view port = "443";

                // we now copy the derived port into char array
                int num_of_chars_copied = port.copy(c_port, port.size());

                // we null terminate the c_port array
                c_port[num_of_chars_copied] = '\0';

                // we call our connect to server function with the interface parameters set to null
                int sockfd = connect_to_server(c_host, c_port, nullptr, nullptr);
                
                if(!error){ // only continue if no error

                    // getting here the connect to server function returned successfully so now we bind the returned socket fd to our c_ssl object
                    wolfSSL_set_fd(c_ssl, sockfd);

                    // we set the application layer protocol for our ssl object to http2
                    wolfSSL_UseALPN(c_ssl, (char*)"h2", 2, WOLFSSL_ALPN_FAILED_ON_MISMATCH);

                    // we perform our tls handshake - since this is a non blocking socket we loop till our handshake is complete
                    int len;

                    while((len = wolfSSL_connect(c_ssl)) != WOLFSSL_SUCCESS){
                        
                        // we get the error message
                        int err = wolfSSL_get_error(c_ssl, len);

                        // we check if the wolfssl handle is still expecting a read or a write
                        if(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE){

                            continue;

                        }
                        else{

                            // getting here we got a actual error so we set our error flag
                            strncpy(error_buffer, "Error performing tls handshake ", error_buffer_array_length);

                            // we concatenate the wolfssl error
                            wolfSSL_ERR_error_string(err, error_buffer + strlen(error_buffer));
                        
                            error = true;

                            // we break out of this loop
                            break;

                        }

                    }
                
                    if(!error){ // only continue if no error
                
                        // we check if h2 protocol was negotiated
                        char* protocol = nullptr;
                        unsigned short protocol_len = 0;
                        wolfSSL_ALPN_GetProtocol(c_ssl, &protocol, &protocol_len);
                        if(protocol_len != 2 || memcmp(protocol, "h2", 2) != 0){
                            std::cout<<"h2 was not negotiated"<<std::endl;
                        }
                        else{
                            std::cout<<"h2 was negotiated"<<std::endl;
                        }

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
    else{ // the lock client instance has a http connection in open state
        
        memset(error_buffer, '\0', strlen(error_buffer)); // erase any previous error message
        
        error = false; // sets the error flag to false first so the close function can run 
        
        if(close()) // close the open http connection 
            
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

            // since the host_name_end_index already finds the first character out of : and / after the host name we use it to find the port number location if any

            // we first check if the host name end index was either std::string_view::npos or / in which case we know the host wasn't supplied so we store 443 as the host, but if the : character was found then the host was supplied so we just create a sub string view from after the : character to either the / starting the path if supplied, but if not supplied till std::string_view::npos - host_name_end_index - 1 which would be a very large number the copy takes the rest of the url string_view
            std::string_view port = (host_name_end_index == std::string_view::npos || url[host_name_end_index] == '/') ? "443" : url.substr(host_name_end_index + 1, url.find('/', host_name_end_index) - host_name_end_index - 1);

            // we now copy the derived port into char array
            int num_of_chars_copied = port.copy(c_port, port.size());

            // we null terminate the c_port array
            c_port[num_of_chars_copied] = '\0';

            // now we can call the connect to server function that would return the configured socket file descriptor
            int sockfd = connect_to_server(c_host, c_port, interface_address, interface_name);

            if(!error){ // only continue if no error

                // getting here the connect to server function returned successfully so now we bind the returned socket fd to our c_ssl object
                wolfSSL_set_fd(c_ssl, sockfd);

                // we set the application layer protocol for our ssl object to http2
                wolfSSL_UseALPN(c_ssl, (char*)"h2", 2, WOLFSSL_ALPN_FAILED_ON_MISMATCH);

                // we perform our tls handshake - since this is a non blocking socket we loop till our handshake is complete
                int len;

                while((len = wolfSSL_connect(c_ssl)) != WOLFSSL_SUCCESS){
                    
                    // we get the error message
                    int err = wolfSSL_get_error(c_ssl, len);

                    // we check if the wolfssl handle is still expecting a read or a write
                    if(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE){

                        continue;

                    }
                    else{

                        // getting here we got a actual error so we set our error flag
                        strncpy(error_buffer, "Error performing tls handshake ", error_buffer_array_length);
                    
                        error = true;

                        // we break out of this loop
                        break;

                    }

                }
            
                if(!error){ // only continue if no error
            
                    // we fetch the path for this connection

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
                            
                                strncpy(error_buffer, "Error allocating heap memory for lock_client channel path ", error_buffer_array_length);
                                
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
                            
                                strncpy(error_buffer, "Error allocating heap memory for lock_client channel path ", error_buffer_array_length);
                                
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

                }
            
            }
        }
    }
    else{ // not a valid/supported http endpoint
        
        strncpy(error_buffer, "Supplied URL parameter is not a valid/supported HTTP endpoint", error_buffer_array_length);
                
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

    // we bind to the supplied interface if any
    if(interface_name != nullptr){

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

    }

    // we bind to the supplied interface address if any
    if(interface_address != nullptr){

        // Set up local address structure
        struct sockaddr_in localaddr;
        memset(&localaddr, 0, sizeof(localaddr));
        localaddr.sin_family = AF_INET;
        localaddr.sin_addr.s_addr = interface_address->s_addr;
        localaddr.sin_port = 0;  // Lets the system choose port

        // Bind socket to specific interface
        if(bind(sock, (struct sockaddr*)&localaddr, sizeof(localaddr)) < 0) {
            // if the binding fails the library does not set the error flag to true it just prints the error message, ignores the specified interface and attempts to make the connection with whatever network interface is available
            std::cout<<"Lockws Error: Binding To Supplied Interface Address Failed...Connection Will Be Attempted With The Default Network Interface Address..."<<std::endl;
        }

    }

    // Set up hints for getaddrinfo
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;      // IPv4 (use AF_UNSPEC for both IPv4 and IPv6)
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets

    // Perform DNS resolution
    if(getaddrinfo(hostname, port, &hints, &res) != 0) {
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

int lock_http2_client_nb::reset(){

    if(!c_ssl) return 0;

    // we fetch the active socket fd
    int sockfd = wolfSSL_get_fd(c_ssl);

    // if a valid socket is bound, we first close it effectively disconnecting it
    if(sockfd >= 0) ::close(sockfd);

    // we now clear our wolfssl session
    wolfSSL_set_fd(c_ssl, -1);
    wolfSSL_clear(c_ssl);

    return 0;

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
     
bool lock_http2_client_nb::close(){ // this closes an established http connection although the object itself still exists till it goes out of scope, the object can be connected to a different or the same http server using the connect function

    if(!error){ // only continue if no error
                
    }
    
    return error; // returning an error of 1 from the close function just means that the close was not a clean one but it was successful nonetheless, and the close function does not write any message to the error buffer
}

#pragma GCC diagnostic pop