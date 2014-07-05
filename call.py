#!/usr/bin/env python
# -*- coding:utf-8 -*-
import dbus
bus = dbus.SessionBus()
bus_obj = bus.get_object('xuc.manager', '/')

interface = dbus.Interface(bus_obj, 'xuc.manager.interface')
ret = interface.GetProperties()
print ret
interface.SetProperty("my_property", 123)

