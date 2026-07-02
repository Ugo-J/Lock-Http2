// non blocking lock client
template <typename T>
class lock_http2_client_nb_crtp {
    
public:
    
    //constructors
    lock_http2_client_nb_crtp(std::string_view url);
    lock_http2_client_nb_crtp(std::string_view url, in_addr* interface_address, char* interface_name); // constructor that binds to a particular interface before connection
    lock_http2_client_nb_crtp(); // parameterless constructor
    
    // destructor
    ~lock_http2_client_nb_crtp();

public:
    
    // public functions
    bool ping(); // ping function
    bool send(std::string_view); //send function
    bool connect(std::string_view); // function to connect to a url
    bool interface_connect(std::string_view url, in_addr* interface_address, char* interface_name); // connect function that binds to a particular interface before connection
    bool close(); // closes an open connection of a lock_http2_client_crtp instance
    bool status(); // checks the error status of a lock_http2_client_crtp instance
    bool is_open();
    char* get_error_message();
    bool basic_read();
    bool clear(); // this function is used to clear the error flags of lock clients in open state, error flags of lock clients in closed state can only be cleared by calling the connect function

protected:
// receive functions
    
    // receive function
    int recv_data(char*, int, int);
    
// protected class functions
protected:
    
    inline void block_sigpipe_signal(); // function to block sigpipe signals before any write or read
    void unblock_sigpipe_signal(); // function to unblock sigpipe signals after any write or read
    int connect_to_server(const char *hostname, const char *port, in_addr* interface_address, const char *interface_name); // function to connect to server when we manually configure the socket

// protected signal handling variables
protected: 
    
    sigset_t oldset; // sigset variable for holding the old signal mask
    sigset_t newset; // sigset variable for holding the signal mask of the signal(s) we wish to block
    siginfo_t si; // siginfo variable for storing the info of blocked signals
    timespec ts = {0}; // structure that stores the time wait for the sigtimedwait function to return, it is initialised to 0 meaning that we don't wait
    
// class wide variables    
protected:    
    
    inline static SSL_CTX* ssl_ctx = NULL;
    
// instance connection data variables     
protected:
    
    static const int url_static_array_length = 1024;
    char c_url_static[url_static_array_length] = {'\0'}; // this url to which the connection is to be made is copied into this array
    uint64_t size_of_allocated_url_memory = 0;
    char* c_url_new = NULL;
    char* c_url = NULL;
    static const int path_static_array_length = 512; 
    char c_path_static[path_static_array_length] = {'\0'}; // static array for holding the channel path
    uint64_t size_of_allocated_path_memory = 0;
    char* c_path_new = NULL; 
    char* c_path = NULL;
    static const int host_static_array_length = 128;
    char c_host_static[host_static_array_length] = {'\0'}; // static array for holding the hostname
    uint64_t size_of_allocated_host_memory = 0;
    char* c_host_new = NULL;
    char* c_host = NULL;
    static const int error_buffer_array_length = 256;
    char error_buffer[error_buffer_array_length] = {'\0'};
    bool error = false;
    unsigned char client_state = CLOSED; // this variable is used to store the lock client state, OPEN meaning there is an active websocket connection and CLOSED meaning that there isn't 
    
// Openssl Library instance variables    
protected:
 
   BIO* c_bio = NULL; // sets the lock_http2_client_crtp instance connection handle
   SSL* c_ssl = NULL; // defines the ssl object that is used to set instance-specific openssl options

// lock client states
protected: 
    
    inline static const unsigned char OPEN = (unsigned char)0;
    inline static const unsigned char CLOSED = (unsigned char)1;
   
// instance variables for sending data
protected:

    static const int send_data_array_len = 64 * 1024; // 64KB
    unsigned char send_data_static[send_data_array_len] = {'\0'};
    uint64_t size_of_allocated_send_data_memory = 0;
    char* send_data_new = NULL;
    char* send_data = NULL;

// instance variables for receiving data
protected:
    
    inline static const int static_data_array_length = 64*1024; // received received data static array length 64KB
    char data_array_static[static_data_array_length] = {'\0'}; // static array for holding received data
    char* data_array_new = NULL;
    char* data_array = NULL;
    char* cursor = NULL; // this is used to keep track of and arrange fragmented messages in order
    uint64_t size_of_allocated_data_memory = 0L;
    uint64_t length_of_array = 0L;
    
};
