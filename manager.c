#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <net/if.h>

#include <glib.h>
#include <dbus/dbus.h>
//#include <gdbus.h>

#ifdef NEED_DBUS_WATCH_GET_UNIX_FD
#define dbus_watch_get_unix_fd dbus_watch_get_fd
#endif

 #define MNG_DBG(args...) \
		do{ \
			printf("[MNG_DEBUG] %s:%s(). ", __FILE__, __FUNCTION__); printf("" args); \
			printf("\n");} \
		while(0)


#define DISPATCH_TIMEOUT  0

#define info(fmt...)
#define error(fmt...)
#define debug(fmt...)
#define MY_SERVICE			"xuc.manager"

#define MY_MANAGER_INTERFACE	"xuc.manager.interface"
#define MY_MANAGER_PATH		"/"

//gdbus.h
typedef void (* GDBusWatchFunction) (DBusConnection *connection,
							void *user_data);

typedef gboolean (* GDBusSignalFunction) (DBusConnection *connection,
					DBusMessage *message, void *user_data);

DBusConnection *g_dbus_setup_bus(DBusBusType type, const char *name,
							DBusError *error);

DBusConnection *g_dbus_setup_private(DBusBusType type, const char *name,
							DBusError *error);

gboolean g_dbus_request_name(DBusConnection *connection, const char *name,
							DBusError *error);

gboolean g_dbus_set_disconnect_function(DBusConnection *connection,
				GDBusWatchFunction function,
				void *user_data, DBusFreeFunction destroy);

typedef void (* GDBusDestroyFunction) (void *user_data);

typedef DBusMessage * (* GDBusMethodFunction) (DBusConnection *connection,
					DBusMessage *message, void *user_data);

typedef guint32 GDBusPendingReply;

typedef void (* GDBusSecurityFunction) (DBusConnection *connection,
						const char *action,
						gboolean interaction,
						GDBusPendingReply pending);

typedef enum {
	G_DBUS_METHOD_FLAG_DEPRECATED = (1 << 0),
	G_DBUS_METHOD_FLAG_NOREPLY    = (1 << 1),			//调用不返回，阻塞
	G_DBUS_METHOD_FLAG_ASYNC      = (1 << 2),
} GDBusMethodFlags;

typedef enum {
	G_DBUS_SIGNAL_FLAG_DEPRECATED = (1 << 0),
} GDBusSignalFlags;

typedef enum {
	G_DBUS_PROPERTY_FLAG_DEPRECATED = (1 << 0),
} GDBusPropertyFlags;

typedef enum {
	G_DBUS_SECURITY_FLAG_DEPRECATED        = (1 << 0),
	G_DBUS_SECURITY_FLAG_BUILTIN           = (1 << 1),
	G_DBUS_SECURITY_FLAG_ALLOW_INTERACTION = (1 << 2),
} GDBusSecurityFlags;

typedef struct {
	const char *name;
	const char *signature;
	const char *reply;
	GDBusMethodFunction function;
	GDBusMethodFlags flags;
	unsigned int privilege;
} GDBusMethodTable;

typedef struct {
	const char *name;
	const char *signature;
	GDBusSignalFlags flags;
} GDBusSignalTable;

typedef struct {
	const char *name;
	const char *type;
	GDBusPropertyFlags flags;
} GDBusPropertyTable;

typedef struct {
	unsigned int privilege;
	const char *action;
	GDBusSecurityFlags flags;
	GDBusSecurityFunction function;
} GDBusSecurityTable;

struct security_data {
	GDBusPendingReply pending;
	DBusMessage *message;
	const GDBusMethodTable *method;
	void *iface_user_data;
};

struct timeout_handler {
	guint id;
	DBusTimeout *timeout;
};

struct watch_info {
	guint id;
	DBusWatch *watch;
	DBusConnection *conn;
};
/*
struct disconnect_data {
	GDBusWatchFunction function;
	void *user_data;
};
*/

struct generic_data {
	unsigned int refcount;
	GSList *interfaces;
	char *introspect;
};

struct interface_data {
	char *name;
	const GDBusMethodTable *methods;
	const GDBusSignalTable *signals;
	const GDBusPropertyTable *properties;
	void *user_data;
	GDBusDestroyFunction destroy;
};

DBusMessage *g_dbus_create_reply_valist(DBusMessage *message,
						int type, va_list args)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return NULL;

	if (dbus_message_append_args_valist(reply, type, args) == FALSE) {
		dbus_message_unref(reply);
		return NULL;
	}

	return reply;
}
DBusMessage *g_dbus_create_reply(DBusMessage *message, int type, ...)
{
	va_list args;
	DBusMessage *reply;

	va_start(args, type);

	reply = g_dbus_create_reply_valist(message, type, args);

	va_end(args);

	return reply;
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *message, void *user_data)
{
	MNG_DBG("CALL!!\n");

	DBusMessage *reply;
	DBusMessageIter iter;
	char* sigvalue = "xuc is bac!";
	int sigvalue2 = 12345;
		
	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);
	   if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &sigvalue)) {

	 //  if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &sigvalue2)) {
	      fprintf(stderr, "Out Of Memory!\n");
	      exit(1);
	   }

	return reply;

//返回默认消息(null)
//	return g_dbus_create_reply(message, DBUS_TYPE_INVALID);
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessageIter iter, value;
	const char *name;
	int type;
	int value_of_name;

	MNG_DBG("conn %p", conn);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
	{
	//return __connman_error_invalid_arguments(msg);
		MNG_DBG("ERROR!!!dbus_message_iter_init(msg, &iter) == FALSE");
		g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
	}
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
	{
	//return __connman_error_invalid_arguments(msg);
		MNG_DBG("ERROR!!! dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING");
		g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
	}
	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INT32)
	{
	//return __connman_error_invalid_arguments(msg);
		MNG_DBG("ERROR!!! dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INT32");
		g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
	}
	dbus_message_iter_get_basic(&iter, &value_of_name);
	
	//dbus_message_iter_recurse(&iter, &value);
	//type = dbus_message_iter_get_arg_type(&value);
	
	MNG_DBG("NAME =  %s, value_of_name = %d", name, value_of_name);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}



static GDBusMethodTable manager_methods[] = {
	{ "GetProperties",     "",      "a{sv}", get_properties  },
	{ "SetProperty",       "si",    "",      set_property,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ },
};

static GDBusSignalTable manager_signals[] = {
	{ "PropertyChanged", "sv" },
	{ },
};

static void print_arguments(GString *gstr, const char *sig,
						const char *direction)
{
	int i;

	for (i = 0; sig[i]; i++) {
		char type[32];
		int struct_level, dict_level;
		unsigned int len;
		gboolean complete;

		complete = FALSE;
		struct_level = dict_level = 0;
		memset(type, 0, sizeof(type));

		/* Gather enough data to have a single complete type */
		for (len = 0; len < (sizeof(type) - 1) && sig[i]; len++, i++) {
			switch (sig[i]){
			case '(':
				struct_level++;
				break;
			case ')':
				struct_level--;
				if (struct_level <= 0 && dict_level <= 0)
					complete = TRUE;
				break;
			case '{':
				dict_level++;
				break;
			case '}':
				dict_level--;
				if (struct_level <= 0 && dict_level <= 0)
					complete = TRUE;
				break;
			case 'a':
				break;
			default:
				if (struct_level <= 0 && dict_level <= 0)
					complete = TRUE;
				break;
			}

			type[len] = sig[i];

			if (complete)
				break;
		}


		if (direction)
			g_string_append_printf(gstr,
					"\t\t\t<arg type=\"%s\" direction=\"%s\"/>\n",
					type, direction);
		else
			g_string_append_printf(gstr,
					"\t\t\t<arg type=\"%s\"/>\n",
					type);
	}
}
static void generate_interface_xml(GString *gstr, struct interface_data *iface)
{
	const GDBusMethodTable *method;
	const GDBusSignalTable *signal;

	for (method = iface->methods; method && method->name; method++) {
		if (!strlen(method->signature) && !strlen(method->reply))
			g_string_append_printf(gstr, "\t\t<method name=\"%s\"/>\n",
								method->name);
		else {
			g_string_append_printf(gstr, "\t\t<method name=\"%s\">\n",
								method->name);
			print_arguments(gstr, method->signature, "in");
			print_arguments(gstr, method->reply, "out");
			g_string_append_printf(gstr, "\t\t</method>\n");
		}
	}

	for (signal = iface->signals; signal && signal->name; signal++) {
		if (!strlen(signal->signature))
			g_string_append_printf(gstr, "\t\t<signal name=\"%s\"/>\n",
								signal->name);
		else {
			g_string_append_printf(gstr, "\t\t<signal name=\"%s\">\n",
								signal->name);
			print_arguments(gstr, signal->signature, NULL);
			g_string_append_printf(gstr, "\t\t</signal>\n");
		}
	}
}

static void generate_introspection_xml(DBusConnection *conn,
				struct generic_data *data, const char *path)
{
	GSList *list;
	GString *gstr;
	char **children;
	int i;

	g_free(data->introspect);

	gstr = g_string_new(DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE);

	g_string_append_printf(gstr, "<node>\n");

	for (list = data->interfaces; list; list = list->next) {
		struct interface_data *iface = list->data;

		g_string_append_printf(gstr, "\t<interface name=\"%s\">\n",
								iface->name);

		generate_interface_xml(gstr, iface);

		g_string_append_printf(gstr, "\t</interface>\n");
	}

	if (!dbus_connection_list_registered(conn, path, &children))
		goto done;

	for (i = 0; children[i]; i++)
		g_string_append_printf(gstr, "\t<node name=\"%s\"/>\n",
								children[i]);

	dbus_free_string_array(children);

done:
	g_string_append_printf(gstr, "</node>\n");

	data->introspect = g_string_free(gstr, FALSE);
}

static DBusMessage *introspect(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct generic_data *data = user_data;
	DBusMessage *reply;

	if (!dbus_message_has_signature(message, DBUS_TYPE_INVALID_AS_STRING)) {
		error("Unexpected signature to introspect call");
		return NULL;
	}

	if (data->introspect == NULL)
		generate_introspection_xml(connection, data,
						dbus_message_get_path(message));

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &data->introspect,
					DBUS_TYPE_INVALID);

	return reply;
}

static GDBusMethodTable introspect_methods[] = {
	{ "Introspect",	"",	"s", introspect	},
	{ }
};

static struct interface_data *find_interface(GSList *interfaces,
						const char *name)
{
	GSList *list;

	if (name == NULL)
		return NULL;

	for (list = interfaces; list; list = list->next) {
		struct interface_data *iface = list->data;
		if (!strcmp(name, iface->name))
			return iface;
	}

	return NULL;
}

static void generic_unregister(DBusConnection *connection, void *user_data)
{
	struct generic_data *data = user_data;

	g_free(data->introspect);
	g_free(data);
}

static DBusHandlerResult process_message(DBusConnection *connection,
			DBusMessage *message, const GDBusMethodTable *method,
							void *iface_user_data)
{
	DBusMessage *reply;
	
	MNG_DBG("CALL:%s\n", method->name);

	reply = method->function(connection, message, iface_user_data);

	if (method->flags & G_DBUS_METHOD_FLAG_NOREPLY) {
		if (reply != NULL)
			dbus_message_unref(reply);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (method->flags & G_DBUS_METHOD_FLAG_ASYNC) {
		if (reply == NULL)
			return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (reply == NULL)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_connection_send(connection, reply, NULL);
	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static GDBusPendingReply next_pending = 1;
static GSList *pending_security = NULL;
static const GDBusSecurityTable *security_table = NULL;

static gboolean check_privilege(DBusConnection *conn, DBusMessage *msg,
			const GDBusMethodTable *method, void *iface_user_data)
{
	const GDBusSecurityTable *security;

	for (security = security_table; security && security->privilege;
								security++) {
		struct security_data *secdata;
		gboolean interaction;

		if (security->privilege != method->privilege)
			continue;

		secdata = g_new(struct security_data, 1);
		secdata->pending = next_pending++;
		secdata->message = dbus_message_ref(msg);
		secdata->method = method;
		secdata->iface_user_data = iface_user_data;

		pending_security = g_slist_prepend(pending_security, secdata);

		if (security->flags & G_DBUS_SECURITY_FLAG_ALLOW_INTERACTION)
			interaction = TRUE;
		else
			interaction = FALSE;

		if (!(security->flags & G_DBUS_SECURITY_FLAG_BUILTIN) &&
							security->function)
			security->function(conn, security->action,
						interaction, secdata->pending);
		else
			builtin_security_function(conn, security->action,
						interaction, secdata->pending);

		return TRUE;
	}

	return FALSE;
}
static DBusHandlerResult generic_message(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct generic_data *data = user_data;
	struct interface_data *iface;
	const GDBusMethodTable *method;
	const char *interface;

	
	interface = dbus_message_get_interface(message);

	iface = find_interface(data->interfaces, interface);
	if (iface == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	for (method = iface->methods; method &&
			method->name && method->function; method++) {
		if (dbus_message_is_method_call(message, iface->name,
							method->name) == FALSE)
			continue;

		if (dbus_message_has_signature(message,
						method->signature) == FALSE)
			continue;

		if (check_privilege(connection, message, method,
						iface->user_data) == TRUE)
			return DBUS_HANDLER_RESULT_HANDLED;

		return process_message(connection, message, method,
							iface->user_data);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}


static DBusObjectPathVTable generic_table = {
	.unregister_function	= generic_unregister,
	.message_function	= generic_message,
};
static gboolean message_dispatch(void *data)
{
	DBusConnection *conn = data;

	dbus_connection_ref(conn);

	MNG_DBG("message_dispatch start");
	/* Dispatch messages */
	while (dbus_connection_dispatch(conn) == DBUS_DISPATCH_DATA_REMAINS);

	dbus_connection_unref(conn);
	
	MNG_DBG("message_dispatch exit");
	return FALSE;
}
static inline void queue_dispatch(DBusConnection *conn,
						DBusDispatchStatus status)
{
	if (status == DBUS_DISPATCH_DATA_REMAINS)
		g_timeout_add(DISPATCH_TIMEOUT, message_dispatch, conn);
}

gboolean g_dbus_request_name(DBusConnection *connection, const char *name,
							DBusError *error)
{
	int result;

	result = dbus_bus_request_name(connection, name,
					DBUS_NAME_FLAG_DO_NOT_QUEUE, error);

	if (error != NULL) {
		if (dbus_error_is_set(error) == TRUE)
			return FALSE;
	}

	if (result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		if (error != NULL)
			dbus_set_error(error, name, "Name already in use");

		return FALSE;
	}

	return TRUE;
}

static gboolean watch_func(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct watch_info *info = data;
	unsigned int flags = 0;
	DBusDispatchStatus status;

	dbus_connection_ref(info->conn);

	if (cond & G_IO_IN)  flags |= DBUS_WATCH_READABLE;
	if (cond & G_IO_OUT) flags |= DBUS_WATCH_WRITABLE;
	if (cond & G_IO_HUP) flags |= DBUS_WATCH_HANGUP;
	if (cond & G_IO_ERR) flags |= DBUS_WATCH_ERROR;

	dbus_watch_handle(info->watch, flags);

	status = dbus_connection_get_dispatch_status(info->conn);
	queue_dispatch(info->conn, status);

	dbus_connection_unref(info->conn);

	return TRUE;
}
static void watch_info_free(void *data)
{
	struct watch_info *info = data;

	if (info->id > 0) {
		g_source_remove(info->id);
		info->id = 0;
	}

	dbus_connection_unref(info->conn);

	g_free(info);
}

static dbus_bool_t add_watch(DBusWatch *watch, void *data)
{
	DBusConnection *conn = data;
	GIOCondition cond = G_IO_HUP | G_IO_ERR;
	GIOChannel *chan;
	struct watch_info *info;
	unsigned int flags;
	int fd;

	if (!dbus_watch_get_enabled(watch))
		return TRUE;

	info = g_new0(struct watch_info, 1);

	fd = dbus_watch_get_unix_fd(watch);
	chan = g_io_channel_unix_new(fd);

	info->watch = watch;
	info->conn = dbus_connection_ref(conn);

	dbus_watch_set_data(watch, info, watch_info_free);

	flags = dbus_watch_get_flags(watch);

	if (flags & DBUS_WATCH_READABLE) cond |= G_IO_IN;
	if (flags & DBUS_WATCH_WRITABLE) cond |= G_IO_OUT;

	info->id = g_io_add_watch(chan, cond, watch_func, info);

	g_io_channel_unref(chan);

	return TRUE;
}

static void remove_watch(DBusWatch *watch, void *data)
{
	if (dbus_watch_get_enabled(watch))
		return;

	/* will trigger watch_info_free() */
	dbus_watch_set_data(watch, NULL, NULL);
}

static void watch_toggled(DBusWatch *watch, void *data)
{
	/* Because we just exit on OOM, enable/disable is
	 * no different from add/remove */
	if (dbus_watch_get_enabled(watch))
		add_watch(watch, data);
	else
		remove_watch(watch, data);
}

static gboolean timeout_handler_dispatch(gpointer data)
{
	struct timeout_handler *handler = data;

	handler->id = 0;

	/* if not enabled should not be polled by the main loop */
	if (!dbus_timeout_get_enabled(handler->timeout))
		return FALSE;

	dbus_timeout_handle(handler->timeout);

	return FALSE;
}

static void timeout_handler_free(void *data)
{
	struct timeout_handler *handler = data;

	if (handler->id > 0) {
		g_source_remove(handler->id);
		handler->id = 0;
	}

	g_free(handler);
}

static dbus_bool_t add_timeout(DBusTimeout *timeout, void *data)
{
	int interval = dbus_timeout_get_interval(timeout);
	struct timeout_handler *handler;

	if (!dbus_timeout_get_enabled(timeout))
		return TRUE;

	handler = g_new0(struct timeout_handler, 1);

	handler->timeout = timeout;

	dbus_timeout_set_data(timeout, handler, timeout_handler_free);

	handler->id = g_timeout_add(interval, timeout_handler_dispatch,
								handler);

	return TRUE;
}

static void remove_timeout(DBusTimeout *timeout, void *data)
{
	/* will trigger timeout_handler_free() */
	dbus_timeout_set_data(timeout, NULL, NULL);
}

static void timeout_toggled(DBusTimeout *timeout, void *data)
{
	if (dbus_timeout_get_enabled(timeout))
		add_timeout(timeout, data);
	else
		remove_timeout(timeout, data);
}
static void dispatch_status(DBusConnection *conn,
					DBusDispatchStatus status, void *data)
{
	if (!dbus_connection_get_is_connected(conn))
		return;

	queue_dispatch(conn, status);
}
static inline void setup_dbus_with_main_loop(DBusConnection *conn)
{
	dbus_connection_set_watch_functions(conn, add_watch, remove_watch,
						watch_toggled, conn, NULL);

	dbus_connection_set_timeout_functions(conn, add_timeout, remove_timeout,
						timeout_toggled, NULL, NULL);

	dbus_connection_set_dispatch_status_function(conn, dispatch_status,
								NULL, NULL);
}
static gboolean setup_bus(DBusConnection *conn, const char *name,
						DBusError *error)
{
	gboolean result;
	DBusDispatchStatus status;

	if (name != NULL) {
		result = g_dbus_request_name(conn, name, error);

		if (error != NULL) {
			if (dbus_error_is_set(error) == TRUE)
				return FALSE;
		}

		if (result == FALSE)
			return FALSE;
	}

	setup_dbus_with_main_loop(conn);

	status = dbus_connection_get_dispatch_status(conn);
	queue_dispatch(conn, status);

	return TRUE;
}

DBusConnection *g_dbus_setup_bus(DBusBusType type, const char *name,
							DBusError *error)
{
	DBusConnection *conn;

	conn = dbus_bus_get(type, error);

	if (error != NULL) {
		if (dbus_error_is_set(error) == TRUE)
			return NULL;
	}

	if (conn == NULL)
		return NULL;

	if (setup_bus(conn, name, error) == FALSE) {
		dbus_connection_unref(conn);
		return NULL;
	}

	return conn;
}

static void add_interface(struct generic_data *data, const char *name,
				const GDBusMethodTable *methods,
				const GDBusSignalTable *signals,
				const GDBusPropertyTable *properties,
				void *user_data,
				GDBusDestroyFunction destroy)
{
	struct interface_data *iface;

	iface = g_new0(struct interface_data, 1);
	iface->name = g_strdup(name);
	iface->methods = methods;
	iface->signals = signals;
	iface->properties = properties;
	iface->user_data = user_data;
	iface->destroy = destroy;

	data->interfaces = g_slist_append(data->interfaces, iface);
}


static void invalidate_parent_data(DBusConnection *conn, const char *child_path)
{
	struct generic_data *data = NULL;
	char *parent_path, *slash;

	parent_path = g_strdup(child_path);
	slash = strrchr(parent_path, '/');
	if (slash == NULL)
		goto done;

	if (slash == parent_path && parent_path[1] != '\0')
		parent_path[1] = '\0';
	else
		*slash = '\0';

	if (!strlen(parent_path))
		goto done;

	if (dbus_connection_get_object_path_data(conn, parent_path,
							(void *) &data) == FALSE) {
		goto done;
	}

	invalidate_parent_data(conn, parent_path);

	if (data == NULL)
		goto done;

	g_free(data->introspect);
	data->introspect = NULL;

done:
	g_free(parent_path);
}




static struct generic_data *object_path_ref(DBusConnection *connection,
							const char *path)
{
	struct generic_data *data;

	if (dbus_connection_get_object_path_data(connection, path,
						(void *) &data) == TRUE) {
		if (data != NULL) {
			data->refcount++;
			return data;
		}
	}

	data = g_new0(struct generic_data, 1);
	data->refcount = 1;

	data->introspect = g_strdup(DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE "<node></node>");

	if (!dbus_connection_register_object_path(connection, path,
						&generic_table, data)) {
		g_free(data->introspect);
		g_free(data);
		return NULL;
	}

	invalidate_parent_data(connection, path);

	add_interface(data, DBUS_INTERFACE_INTROSPECTABLE,
			introspect_methods, NULL, NULL, data, NULL);

	return data;
}



static gboolean remove_interface(struct generic_data *data, const char *name)
{
	struct interface_data *iface;

	iface = find_interface(data->interfaces, name);
	if (iface == NULL)
		return FALSE;

	data->interfaces = g_slist_remove(data->interfaces, iface);

	if (iface->destroy)
		iface->destroy(iface->user_data);

	g_free(iface->name);
	g_free(iface);

	return TRUE;
}

static void object_path_unref(DBusConnection *connection, const char *path)
{
	struct generic_data *data = NULL;

	if (dbus_connection_get_object_path_data(connection, path,
						(void *) &data) == FALSE)
		return;

	if (data == NULL)
		return;

	data->refcount--;

	if (data->refcount > 0)
		return;

	remove_interface(data, DBUS_INTERFACE_INTROSPECTABLE);

	invalidate_parent_data(connection, path);

	dbus_connection_unregister_object_path(connection, path);
}

gboolean g_dbus_register_interface(DBusConnection *connection,
					const char *path, const char *name,
					const GDBusMethodTable *methods,
					const GDBusSignalTable *signals,
					const GDBusPropertyTable *properties,
					void *user_data,
					GDBusDestroyFunction destroy)
{
	struct generic_data *data;
	
	MNG_DBG("register interface:%s\n", name);
	data = object_path_ref(connection, path);
	if (data == NULL)
		return FALSE;

	if (find_interface(data->interfaces, name)) {
		object_path_unref(connection, path);
		return FALSE;
	}

	add_interface(data, name, methods, signals,
			properties, user_data, destroy);

	g_free(data->introspect);
	data->introspect = NULL;

	return TRUE;
}

static GMainLoop *main_loop = NULL;

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	DBusConnection *conn;
	DBusError err;
	GKeyFile *config;
	guint signal;
	static guint my_signal_watch;

#if 0  	
	daemon(0, 1);
        sleep(1);
#endif

	printf("\n------   dtv manager v1.1  ------  \n\n");
	
	main_loop = g_main_loop_new(NULL, FALSE);
	dbus_error_init(&err);

	conn = g_dbus_setup_bus(DBUS_BUS_SESSION, MY_SERVICE, &err);
	if (conn == NULL) {
		if (dbus_error_is_set(&err) == TRUE) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		} else
			fprintf(stderr, "Can't register with system bus\n");
		exit(1);
	}

	g_dbus_register_interface(conn, MY_MANAGER_PATH,
					MY_MANAGER_INTERFACE,
					manager_methods,
					manager_signals, NULL, NULL, NULL);


	/*
	my_signal_watch = g_dbus_add_signal_watch(conn, NULL, NULL,
						MY_MANAGER_INTERFACE,
						MODEM_ADDED,
						modem_added,
						NULL, NULL);	
	*/


	printf("enter main loop\n");
	
	g_main_loop_run(main_loop);
	
	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	return 0;
}
  
