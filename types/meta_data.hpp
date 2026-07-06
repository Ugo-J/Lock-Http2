// this header file defines the meta data struct that passed as the user data to every nghttp2 request

struct meta_data {

    char* data_array = nullptr;
    char* cursor = nullptr;
    int array_size = 0;
    int array_index; // this holds the index of this metadata in the meta data array - we use this to keep track of which meta data points to heap memory, any array index > our static array size is pointing to a heap location
    int user_id; // this is the user supplied id that is passed back to the user supplied receive data function

};
