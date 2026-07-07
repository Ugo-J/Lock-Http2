using lock_function = std::function<int(char*, int, int, int)>;

// non blocking lock client
class lock_http2_client_nb {
    
public:
    
    //constructors
    lock_http2_client_nb(std::string_view url);
    lock_http2_client_nb(std::string_view url, in_addr* interface_address, char* interface_name); // constructor that binds to a particular interface before connection
    lock_http2_client_nb(); // parameterless constructor
    
    // destructor
    ~lock_http2_client_nb();

public:
    
    // public functions
    bool ping(); // ping function
    bool send(std::string_view path, char* payload, int method, int id); // send function
    bool connect(std::string_view); // function to connect to a url
    bool interface_connect(std::string_view url, in_addr* interface_address, char* interface_name); // connect function that binds to a particular interface before connection
    bool close(); // closes an open connection of a lock_http2_client instance
    bool status(); // checks the error status of a lock_http2_client instance
    bool is_open();
    char* get_error_message();
    bool basic_read();
    bool clear(); // this function is used to clear the error flags of lock clients in open state, error flags of lock clients in closed state can only be cleared by calling the connect function
    inline static int default_receive(char*, int, int, int); // default receive function called by basic read
    void set_receive_function(lock_function fn);

private:
// pointers to receive functions
    
    // receive function pointer
    lock_function recv_data = lock_http2_client_nb::default_receive;
    
// private class functions
private:
    
    inline void block_sigpipe_signal(); // function to block sigpipe signals before any write or read
    void unblock_sigpipe_signal(); // function to unblock sigpipe signals after any write or read
    int connect_to_server(const char *hostname, const char *port, in_addr* interface_address, const char *interface_name); // function to connect to server when we manually configure the socket
    int reset(); // function to reset a wolfssl session and disconnect the underlying connection

// nghttp2 callback functions
private:

    // on frame receive call back function
    static int on_frame_recv_cb(nghttp2_session *session, const nghttp2_frame *frame, void *user_data);

    // on data chunk receive callback
    static int on_data_chunk_recv_cb(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data);

    // on stream close callback
    static int on_stream_close_cb(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data);

    // on header callback
    static int on_header_cb(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data);

    // send body provider callback - this function is called when nghttp2 needs more data to send
    static long send_body_provider_cb(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data);

// data handling functions - these are the functions the nghttp2 callbacks call
private:

    int handle_frame_recv(const nghttp2_frame *frame);
    int handle_header(const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags);
    int handle_data_chunk(uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len);
    int handle_stream_close(int32_t stream_id, uint32_t error_code);

// private signal handling variables
private: 
    
    sigset_t oldset; // sigset variable for holding the old signal mask
    sigset_t newset; // sigset variable for holding the signal mask of the signal(s) we wish to block
    siginfo_t si; // siginfo variable for storing the info of blocked signals
    timespec ts = {0}; // structure that stores the time wait for the sigtimedwait function to return, it is initialised to 0 meaning that we don't wait
    
// class wide variables    
private:    
    
    WOLFSSL_CTX* ssl_ctx = NULL;

    // static memory for wolfssl because we disabled dynamic allocation on the hot path
    static constexpr size_t CRYPTO_ARENA_SIZE = 256 * 1024;
    alignas(16) uint8_t crypto_memory_pool[CRYPTO_ARENA_SIZE];
    alignas(16) uint8_t general_memory_pool[CRYPTO_ARENA_SIZE];
    
// instance connection data variables     
private:
    
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
    
// wolfssl Library instance variables    
private:
        
   WOLFSSL* c_ssl = NULL; // defines the ssl object that is used to set instance-specific wolfssl options
   nghttp2_session* session; // nghttp2 session object pointer
   static constexpr unsigned int MAX_CONCURRENT_STREAMS = 32 + 64; // this holds the max number of streams each lockhttp2 client can hold. a stream is essentially a request to a server pending a response, so the max concurrent streams is essentially the number of unresponded streams we can have on this handle. we set the max concurrent streams to account for our total available data arrays which is 32 for the static array and 64 for the heap array

// lock client states
private: 
    
    inline static const unsigned char OPEN = (unsigned char)0;
    inline static const unsigned char CLOSED = (unsigned char)1;

// instance variables for receiving data
private:
    
    // we declare our meta data array, our meta data array is declared large enough to hold the metadata for our max concurrent streams
    meta_data metadata[MAX_CONCURRENT_STREAMS];

    static constexpr int STATIC_ARRAY_SIZE = 4 * 1024; // we set our static data array size to 4KB
    static constexpr int NUM_OF_STATIC_ARRAYS = 32; // we set our number of static arrays. any meta data with array index greater than num of static arrays - 1 was declared off the heap
    char static_array[NUM_OF_STATIC_ARRAYS][STATIC_ARRAY_SIZE];

// acquire & release functions for acquiring the next free static array
private:

    // we use the static mask to keep track of the free arrays in our static arrays for receiving stream data
    uint32_t static_mask = 0xFFFFFFFF;

    // we use the heap mask to keep track of the free metadata locations for receiving stream data to our heap locations
    uint64_t heap_mask = 0xFFFFFFFFFFFFFFFF;

    int acquire();

    // this function is used to acquire a particular heap location with a specified memory size
    int acquire_heap(int sz);

    void release(int slot);

// variable for receiving the http2 binary data from the network before passing it to http2
private:

    inline static const int DATA_ARRAY_LENGTH = 32 * 1024;
    char data_array[DATA_ARRAY_LENGTH] = {'\0'}; // array for holding received data before passing to nghttp2

// http methods
public:

    static inline constexpr int GET = 0;
    static inline constexpr int POST = 1;
    static inline constexpr int PUT = 2;
    static inline constexpr int PATCH = 3;
    static inline constexpr int DELETE = 4;

// array to convert the http method to their corresponding text
private:

    static constexpr const char* methods[] = {"GET", "POST", "PUT", "PATCH", "DELETE"};

// variables for managing http headers
private:

    // this variable holds the maximum number of headers we can handle in a http request
    static constexpr int MAX_NUM_OF_HEADERS = 64;

    // this variable holds the maximum length of a header item - name or value - that we can handle
    static constexpr int MAX_HEADER_ITEM_LENGTH = 128;

    // this array holds all our header names
    char h_name[MAX_NUM_OF_HEADERS][MAX_HEADER_ITEM_LENGTH];

    // this array holds all our header values
    char h_value[MAX_NUM_OF_HEADERS][MAX_HEADER_ITEM_LENGTH];

    // this is the struct that holds the headers we pass to our submit request, the nghttp2_nv struct has the following fields uint8_t* name, uint8_t* value, size_t namelen, size_t valuelen, uint8_t flags
    nghttp2_nv hdrs[MAX_NUM_OF_HEADERS];

    // this variables holds the number of valid headers in our hdrs struct to pass to our submit request
    int num_of_headers = 0;

// functions for managing http headers
public:

    // function to set a header
    char* set_header(char* name, char* value);

    // function to return the value of a header
    char* get_header(char* name);

    // function to clear a header from the header list
    int clear_header(char* name);

    // function to clear all user defined headers leaving only the http2 pseudo headers
    int clear_headers();

    
};
