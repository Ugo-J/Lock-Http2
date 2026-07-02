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
template <typename T>
lock_http2_client_nb_crtp<T>::lock_http2_client_nb_crtp(std::string_view url, in_addr* interface_address, char* interface_name){

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
        else{ // not a valid/supported http endpoint
            
            strncpy(error_buffer, "Supplied URL parameter is not a valid/supported HTTP endpoint", error_buffer_array_length);
                    
            error = true;
            
        }

    }

}

// parameterless constructor
template <typename T>
lock_http2_client_nb_crtp<T>::lock_http2_client_nb_crtp(){
    
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
    
}

// destructor
template <typename T>
lock_http2_client_nb_crtp<T>::~lock_http2_client_nb_crtp(){
    
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

    if(client_state == OPEN)
        return true;
    else
        return false;
    
}

template <typename T>
bool lock_http2_client_nb_crtp<T>::ping(){ // sends a ping on an established http connection
    
    if(!error){ // only continue if no error
        
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
bool lock_http2_client_nb_crtp<T>::send(std::string_view payload_data){ // sends data passed as parameter along an established http connection

    if(!error){ // only continue if no error
    
    }
        
    return error;
    
}

template <typename T>
inline int lock_http2_client_nb_crtp<T>::recv_data(char* data_array, int length_of_array_data, int length_of_array){
    
    // we call the derived class recv data implementation
    return static_cast<T*>(this)->recv_data(data_array, length_of_array_data, length_of_array);
    
}

template <typename T>
inline int lock_http2_client_nb_crtp<T>::recv_pong(char* data_array, int length_of_array_data, int length_of_array){
    
    // we call the derived class recv pong implementation
    return static_cast<T*>(this)->recv_pong(data_array, length_of_array_data, length_of_array);
    
}

template <typename T>
bool lock_http2_client_nb_crtp<T>::basic_read(){

    if(!error){ // only continue if no error
        
    }
        
    return error;
        
}

template <typename T>
bool lock_http2_client_nb_crtp<T>::connect(std::string_view url){ // this is used to connect to connect to the url passed as a parameter, it can be used when a lock client object was created without establishing a http connection by using the parameterless constructor, or to connect an already established http connection and lock client instance to a different http server, it can also be used to retry connecting an instance that encountered an error during connection
    
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

    return error;
        
}

template <typename T>
bool lock_http2_client_nb_crtp<T>::interface_connect(std::string_view url, in_addr* interface_address, char* interface_name){
    
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
    else{ // not a valid/supported http endpoint
        
        strncpy(error_buffer, "Supplied URL parameter is not a valid/supported HTTP endpoint", error_buffer_array_length);
                
        error = true;
        
    }


    return error;
}

template <typename T>
int lock_http2_client_nb_crtp<T>::connect_to_server(const char *hostname, const char *port, in_addr* interface_address, const char *interface_name){

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
            close(sock);
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
        close(sock);
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

template <typename T>
int lock_http2_client_nb_crtp<T>::reset(){

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
bool lock_http2_client_nb_crtp<T>::close(unsigned short status_code){ // this closes an established http connection although the object itself still exists till it goes out of scope, the object can be connected to a different or the same http server using the connect function

    if(!error){ // only continue if no error
                
    }
    
    return error; // returning an error of 1 from the close function just means that the close was not a clean one but it was successful nonetheless, and the close function does not write any message to the error buffer
}

#pragma GCC diagnostic pop