#include <dbus/dbus.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
/** 
 * Call a method on a remote object 
 */ 
void get()   
{  
   DBusMessage* msg;  
   DBusMessageIter args;  
   DBusConnection* conn;  
   DBusError err;  
   DBusPendingCall* pending;  
   int ret;  
   bool stat;  
   dbus_uint32_t level;  
   
   printf("get\n");  
   // initialiset the errors  
   dbus_error_init(&err);  
   
   // connect to the system bus and check for errors  
   conn = dbus_bus_get(DBUS_BUS_SESSION, &err);  
   if (dbus_error_is_set(&err)) {   
      fprintf(stderr, "Connection Error (%s)\n", err.message);   
      dbus_error_free(&err);  
   }  
   if (NULL == conn) {   
      exit(1);   
   }  
   
   // request our name on the bus  
   ret = dbus_bus_request_name(conn, "xuc.client.interface", DBUS_NAME_FLAG_REPLACE_EXISTING , &err);  
   if (dbus_error_is_set(&err)) {   
      fprintf(stderr, "Name Error (%s)\n", err.message);   
      dbus_error_free(&err);  
   }  
   if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret) {   
      exit(1);  
   }  
   
   // create a new method call and check for errors  
   msg = dbus_message_new_method_call("xuc.manager", // target for the method call  
                                      "/", // object to call on  
                                      "xuc.manager.interface", // interface to call on  
                                      "GetProperties"); // method name  
   if (NULL == msg) {   
      fprintf(stderr, "Message Null\n");  
      exit(1);  
   }  
   
   // send message and get a handle for a reply  
   if (!dbus_connection_send_with_reply (conn, msg, &pending, -1)) { // -1 is default timeout  
      fprintf(stderr, "Out Of Memory!\n");   
      exit(1);  
   }  
   if (NULL == pending) {   
      fprintf(stderr, "Pending Call Null\n");   
      exit(1);   
   }  
   dbus_connection_flush(conn);  
       
   printf("Request Sent\n");  
       
   // free message  
   dbus_message_unref(msg);  
       
   // block until we recieve a reply  
   dbus_pending_call_block(pending);  
   
   // get the reply message  
   msg = dbus_pending_call_steal_reply(pending);  
   if (NULL == msg) {  
      fprintf(stderr, "Reply Null\n");   
      exit(1);   
   }  
   // free the pending message handle  
   dbus_pending_call_unref(pending);  
   
   // read the first parameters  
   const char * ret_msg;   

   if (!dbus_message_iter_init(msg, &args))  
      fprintf(stderr, "Message has no arguments!\n");   
   else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))   
      fprintf(stderr, "Argument is not char*!\n");   
   else 
      dbus_message_iter_get_basic(&args, &ret_msg);  
   
   // read the second  parameters 
 /*
   if (!dbus_message_iter_next(&args))  
      fprintf(stderr, "Message has too few arguments!\n");   
   else if (DBUS_TYPE_UINT32 != dbus_message_iter_get_arg_type(&args))   
      fprintf(stderr, "Argument is not int!\n");   
   else 
      dbus_message_iter_get_basic(&args, &level);  
   */
   //printf("Got Reply: %d, %d\n", stat, level);  
   printf("Got Reply: %s \n", ret_msg);  
       
   // free reply   
   dbus_message_unref(msg);     
}  
   
void set(char* name, int value_of_name)   
{  
   DBusMessage* msg;  
   DBusMessageIter args;  
   DBusConnection* conn;  
   DBusError err;  
   DBusPendingCall* pending;  
   int ret;  
   bool stat;  
   dbus_uint32_t level;  
   
   printf("set\nname = %s,value = %d\n", name , value_of_name);  
   
   // initialiset the errors  
   dbus_error_init(&err);  
   
   // connect to the system bus and check for errors  
   conn = dbus_bus_get(DBUS_BUS_SESSION, &err);  
   if (dbus_error_is_set(&err)) {   
      fprintf(stderr, "Connection Error (%s)\n", err.message);   
      dbus_error_free(&err);  
   }  
   if (NULL == conn) {   
      exit(1);   
   }  
   
   // request our name on the bus  
   ret = dbus_bus_request_name(conn, "xuc.client.interface2", DBUS_NAME_FLAG_REPLACE_EXISTING , &err);  
   if (dbus_error_is_set(&err)) {   
      fprintf(stderr, "Name Error (%s)\n", err.message);   
      dbus_error_free(&err);  
   }  
   if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret) {   
      exit(1);  
   }  
   
   // create a new method call and check for errors  
   msg = dbus_message_new_method_call("xuc.manager", // target for the method call  
                                      "/", // object to call on  
                                      "xuc.manager.interface", // interface to call on  
                                      "SetProperty"); // method name  
   if (NULL == msg) {   
      fprintf(stderr, "Message Null\n");  
      exit(1);  
   }  
   
   // append arguments  

   dbus_message_iter_init_append(msg, &args);  
   if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &name)) {  
      fprintf(stderr, "Out Of Memory!\n");   
      exit(1);  
   }
   if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_INT32, &value_of_name)) {  
      fprintf(stderr, "Out Of Memory!\n");   
      exit(1);  
   }  
       

   // send message and get a handle for a reply  
   if (!dbus_connection_send_with_reply (conn, msg, &pending, -1)) { // -1 is default timeout  
      fprintf(stderr, "Out Of Memory!\n");   
      exit(1);  
   }  
   if (NULL == pending) {   
      fprintf(stderr, "Pending Call Null\n");   
      exit(1);   
   }  
   dbus_connection_flush(conn);  
       
   printf("Request Sent\n");  
   // free message  
   dbus_message_unref(msg);  
    
}  
 
 
 
int main(int argc, char** argv)
{
    get();
    
    char* param = "my_property"; 
    int num = 789;
    set("my_property!", num);
    return 0;
} 
