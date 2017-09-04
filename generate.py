"""
Generate C++ code from the Wayland XML spec
"""

from __future__ import print_function

import argparse
import os
from os import path
import sys
from string import Template
import textwrap
import re
from xml.etree import ElementTree


def write_if_different(outpath, content):
    if path.exists(outpath):
        with open(outpath, 'rb') as f:
            old_content = f.read()
        if old_content == content:
            return
    with open(outpath, 'wb') as out:
        out.write(content)


def render(tmpl, **kwargs):
    return Template(tmpl).substitute(**kwargs)


def render_lines(lines, **kwargs):
    return render(''.join(l + '\n' for l in lines), **kwargs)


def render_block(block, indent=0, **kwargs):
    lines = textwrap.dedent(block).splitlines()
    return render_lines([(' ' * indent + l) for l in lines],
                        **kwargs).lstrip(' ').rstrip()


def c_type(t):
    return {
        'fixed': 'double',
        'string': 'const char*',
        'object': '::wl_proxy*',
        'uint': 'std::uint32_t',
        'fd': 'int',
        'new_id': 'void*',
        'int': 'int',
        'array': '::wl_array',
    }[t]


class Description(object):
    def __init__(self, parent, node):
        self.parent = parent
        self.node = node
        self.summary = node.attrib['summary']
        self.content = node.text

    @staticmethod
    def on(who):
        desc = who.node.find('description')
        if desc is not None:
            return Description(who, desc)
        return None


class EnumEntry(object):
    def __init__(self, parent, node):
        self.parent = parent
        self.node = node
        self.name = node.attrib['name']
        self.value = int(node.attrib['value'], 0)
        self.summary = node.attrib['summary']

    def render(self, indent):
        return render_block(
            '''\
            // $summary
            $name = $value,
            ''',
            indent=indent,
            summary=self.summary,
            name=self.sanitized_name,
            value=self.value)

    @property
    def sanitized_name(self):
        if re.match(r'\d+', self.name):
            return '_' + self.name
        if self.name in ['default']:
            return self.name + '_'
        return self.name


class EnumType(object):
    def __init__(self, parent, node):
        self.parent = parent
        self.node = node
        self.name = node.attrib['name']
        self.description = Description.on(self)
        self.entries = [EnumEntry(self, n) for n in node.iter('entry')]

    def render(self, indent):
        content = render_block(
            '''\
            enum class $name {
                $values
            };
            ''',
            indent=indent,
            name=self.name,
            values=self._render_entries(indent + 4))
        return content

    def _render_entries(self, indent):
        return ''.join(e.render(indent) for e in self.entries)


class ReturnType(object):
    def __init__(self, parent, node):
        self.parent = parent
        self.node = node
        self.arg = None if node is None else Argument(parent, node)

    @property
    def wl_type(self):
        if self.node is None:
            return None
        if self.node.attrib['type'] == 'new_id':
            iface = self.node.get('interface')
            if iface is not None:
                return iface[3:]
        return None

    @property
    def cpp_typename(self):
        if self.node is None:
            return 'void'
        if self.node.attrib['type'] == 'new_id':
            iface = self.node.get('interface')
            if iface is not None:
                return 'wl::' + iface[3:]
            return 'int'

        return self.node.attrib['type']


class Argument(object):
    def __init__(self, parent, node):
        self.parent = parent
        self.node = node
        self.name = node.attrib['name']
        self.enum_id = node.get('enum')

    @property
    def arg_name(self):
        return self.name + '_'

    @property
    def sigstr(self):
        c = {
            'int': 'i',
            'uint': 'u',
            'fixed': 'f',
            'string': 's',
            'object': 'o',
            'new_id': 'n',
            'array': 'a',
            'fd': 'h',
        }[self.node.attrib['type']]
        if self.node.get('allow-null'):
            return '?' + c
        if c == 'n' and self.node.get('interface') is None:
            return 'sun'
        return c

    @property
    def c_call_expr(self):
        t = self.node.attrib['type']
        if t == 'object':
            return self.arg_name + '.get()'
        elif t == 'new_id':
            return 'nullptr'
        elif t == 'string':
            return self.arg_name + '.data()'
        else:
            return self.arg_name

    @property
    def cpp_call_expr(self):
        t = self.node.attrib['type']
        if t == 'object':
            return render_block(
                '''
                ${type}(std::move($name))
                ''',
                type=self.referenced_type[1] or '',
                iface=self.node.get('interface', 'void'),
                name=self.arg_name)
        return 'static_cast<{}>({})'.format(self.cpp_typename, self.arg_name)

    def cpp_param_decl(self, cvr=''):
        ref_type = self.cpp_typename
        if ref_type is not None:
            return ref_type + ' ' + cvr + ' ' + self.arg_name
        return self.cpp_typename + ' ' + self.arg_name

    @property
    def c_param_decl(self):
        return '{t} {n}'.format(
            t=c_type(self.node.attrib['type']), n=self.arg_name)

    @property
    def cpp_typename(self):
        iface = self.node.get('interface')
        if iface is not None:
            return 'wl::' + iface[3:]
        if self.node.attrib['type'] == 'object':
            return 'void*'
        if self.enum_id:
            if '.' in self.enum_id:
                iface, name = self.enum_id.split('.')
                classname = iface[3:]
                return 'wl::{}::{}'.format(classname, name)
            else:
                return 'enum ' + self.enum_id

        return self.node.attrib['type']

    @property
    def referenced_type(self):
        iface = self.node.get('interface')
        if iface is not None:
            return False, iface[3:]
        if self.enum_id and '.' in self.enum_id:
            return True, self.enum_id.split('.')[0][3:]
        return False, None

    @property
    def signature_type_ptr(self):
        iface = self.referenced_type[1]
        if iface is None:
            return 'nullptr'
        return '&wl::detail::{}_interface'.format(iface)


class Message(object):
    def __init__(self, parent, index, node):
        self.parent = parent
        self.node = node
        self.index = index
        self.name = node.attrib['name']
        self.description = Description.on(self)

        # Default return type is void
        self.ret = ReturnType(self, None)

        # new_id indicates a return value
        arg_nodes = list(node.iter('arg'))
        new_ids = [n for n in arg_nodes if n.attrib['type'] == 'new_id']
        assert len(new_ids) <= 1
        if len(new_ids):
            self.ret = ReturnType(self, new_ids[0])
            arg_nodes = arg_nodes[1:]
        self.proto_args = [Argument(self, n) for n in node.iter('arg')]
        self.args = [Argument(self, n) for n in arg_nodes]

    def render_wl_message(self):
        sigtype_ptrs = [a.signature_type_ptr for a in self.args]
        if self.ret.arg is not None:
            sigtype_ptrs.insert(0, self.ret.arg.signature_type_ptr)
        sigtype_ptrs = ', '.join(sigtype_ptrs)
        return render_block(
            '''\
            const ::wl_interface* _${name}_sigtypes[] = { $sigtypes };
            ::wl_message _${name}_message = {
                "$name",
                "$sigstr",
                _${name}_sigtypes,
            };
            ''',
            name=self.name,
            sigstr=''.join(a.sigstr for a in self.proto_args),
            sigtypes=sigtype_ptrs)

    def _render_params(self, with_ec=False, cvr=''):
        decls = [a.cpp_param_decl(cvr) for a in self.args]
        if with_ec:
            decls.append('std::error_code& ec')
        return ', '.join(decls)

    def referenced_types(self, include_soft=True):
        ret = []
        rt = self.ret.wl_type
        if rt and include_soft:
            ret.append(rt)
        for arg in self.args:
            hard, rt = arg.referenced_type
            if rt is not None and (hard or include_soft):
                ret.append(rt)
        return ret

    @property
    def c_args(self):
        exprs = [a.c_call_expr for a in self.proto_args]
        return ''.join(', {}'.format(e) for e in exprs)


class Request(Message):
    def render_decl(self, indent):
        if self.name == 'bind' and self.parent.name == 'wl_registry':
            # Special case
            return ''
        return render_block(
            '''\
                $ret_type $cpp_name($params_no_ec);
                $ret_type $cpp_name($params);
            ''',
            indent=indent,
            ret_type=self.ret.cpp_typename,
            cpp_name=self.name,
            params=self._render_params(
                with_ec=True, cvr='const&'),
            params_no_ec=self._render_params(cvr='const&'))

    def render_impl(self):
        if self.name == 'bind' and self.parent.name == 'wl_registry':
            return ''
        return render_block(
            '''\
                $ret_type wl::$parent::$cpp_name($params_no_ec) {
                    error_code ec;
                    $body
                    detail::ec_check(ec, "wl::$parent::$cpp_name()");
                    $ret;
                }
                $ret_type wl::$parent::$cpp_name($params) {
                    $body
                    $ret;
                }
            ''',
            ret_type=self.ret.cpp_typename,
            cpp_name=self.name,
            body=self._render_body(4),
            parent=self.parent.cpp_name,
            params=self._render_params(
                with_ec=True, cvr='const&'),
            params_no_ec=self._render_params(cvr='const&'),
            ret='return'
            if self.ret.cpp_typename is 'void' else 'return std::move(ret)')

    def _render_body(self, indent):
        if self.ret.cpp_typename != 'void':
            return self._render_constructor_body(indent)
        else:
            return self._render_regular_body(indent)

    def _render_constructor_body(self, indent):
        return render_block(
            '''\
            auto old_errno = errno;
            errno = 0;
            ::wl_proxy* new_proxy =
                ::wl_proxy_marshal_constructor(
                    reinterpret_cast<::wl_proxy*>(_impl),
                    $opcode,
                    &$ret_type::interface
                    $args
                );
            ec = detail::ec_from_errno();
            errno = old_errno;
            auto ret = $ret_type(std::move(new_proxy));
            ''',
            indent=indent,
            ret_type=self.ret.cpp_typename,
            opcode=self.index,
            args=self.c_args)

    def _render_regular_body(self, indent):
        return render_block(
            '''\
            auto old_errno = errno;
            errno = 0;
            ::wl_proxy_marshal(reinterpret_cast<::wl_proxy*>(_impl), $opcode$args);
            ec = detail::ec_from_errno();
            errno = old_errno;
            ''',
            opcode=self.index,
            args=self.c_args)


class Event(Message):
    @property
    def function_field(self):
        return render_block(
            'std::function<void($params)> _${name}_handler;',
            params=self.cpp_params(),
            name=self.name)

    @property
    def event_setter(self):
        return render_block(
            '''\
            template <typename Func>
            void on_$name(Func&& fn) {
                _${name}_handler = std::forward<Func>(fn);
            }
            ''',
            name=self.name)

    @property
    def c_params(self):
        params = [a.c_param_decl for a in self.args]
        params.insert(0, '::wl_proxy* _this')
        params.insert(0, 'void* userdata')
        return ', '.join(params)

    def cpp_params(self, cvr=''):
        params = [a.cpp_param_decl(cvr) for a in self.args]
        return ', '.join(params)

    @property
    def cpp_args(self):
        return ', '.join(a.cpp_call_expr for a in self.args)

    @property
    def arg_names(self):
        return ', '.join(a.arg_name for a in self.args)

    def _render_set_members(self, indent):
        return render_block(
            '''\
            std::function<void($params)> _${name}_fn;
            ''',
            indent=indent,
            name=self.name,
            params=self.cpp_params())

    def event_listener(self, indent):
        return render_block(
            r'''\
            reinterpret_cast<void(*)()>(
                (void(*)($c_params))[]($c_params) -> void {
                    // I handle the "$name" event
                    auto self = static_cast<$parent_name*>(userdata);
                    if (self->_${name}_handler) {
                        self->_${name}_handler($cpp_args);
                    } else {
                        std::fprintf(stderr, "Unhandled \"%s\" event on a %s object\n", "$name", "$parent_name");
                    }
                }
            )
            ''',
            indent=indent,
            name=self.name,
            parent_name=self.parent.cpp_name,
            c_params=self.c_params,
            cpp_args=self.cpp_args)


class Interface(object):
    def __init__(self, node):
        self.node = node
        self.name = node.attrib['name']
        self.version = int(node.get('version'))
        self.description = Description.on(self)
        self.enums = [EnumType(self, n) for n in node.iter('enum')]
        self.requests = [Request(self, i, n)
                         for i, n in enumerate(node.iter('request'))]
        self.events = [Event(self, i, n)
                       for i, n in enumerate(node.iter('event'))]

    def write_files(self, odir):
        self.write_header(odir)
        self.write_impl(odir)

    @property
    def cpp_name(self):
        return self.name[3:]

    @property
    def interface_name(self):
        return '{}_interface'.format(self.cpp_name)

    def header_path(self, odir):
        return path.join(odir, self.cpp_name + '.hpp')

    def impl_path(self, odir):
        return path.join(odir, self.cpp_name + '.cpp')

    def print_output_files(self, odir):
        print(self.header_path(odir))
        print(self.impl_path(odir))

    def write_header(self, odir):
        opath = self.header_path(odir)
        if not path.isdir(path.dirname(opath)):
            os.makedirs(path.dirname(opath))

        content = '''\
            #ifndef WL_GEN_${cpp_name_upper}_HPP_INCLUDED
            #define WL_GEN_${cpp_name_upper}_HPP_INCLUDED

            #include <wl/wl.hpp>

            $includes

            #include <functional>

            struct $impl_type;
            struct wl_interface;

            namespace wl {

            $forward_decls

            namespace detail {
                extern ::wl_interface $iface_name;
            }

            class $cpp_name {
            public:
                $enums
            private:
                ::$impl_type* _impl = nullptr;
                $handlers
            public:
                $cpp_name() = delete;
                ~$cpp_name();
                explicit $cpp_name(decltype(nullptr)) {}
                explicit $cpp_name(::$impl_type*&& pr);
                $cpp_name(const $cpp_name&) = delete;
                $cpp_name($cpp_name&& other);

                $cpp_name& operator=(const $cpp_name&) = delete;
                $cpp_name& operator=($cpp_name&& other);

                $request_decls

                $specials_decls

                ::$impl_type* get() const { return _impl; }

                $event_setters

                static constexpr ::wl_interface& interface = detail::$iface_name;

                explicit operator bool() const { return !!_impl; }
            };

            }

            #endif // WL_GEN_${cpp_name_upper}_HPP_INCLUDED
        '''
        handlers = render_block(
            '\n'.join(e.function_field for e in self.events), indent=4)
        event_setters = render_block(
            '\n'.join(e.event_setter for e in self.events), indent=4)
        content = render_block(
            content,
            iface_name=self.interface_name,
            impl_type=self.impl_type,
            handlers=handlers,
            event_setters=event_setters,
            cpp_name=self.cpp_name,
            forward_decls=self._render_forward_decls(),
            includes=self._render_includes(),
            request_decls=self._render_request_decls(4),
            enums=self._render_enums(4),
            specials_decls=render_block(
                _specials_for(self.cpp_name)['decls'], indent=4),
            cpp_name_upper=self.cpp_name.upper())
        write_if_different(opath, content)

    @property
    def impl_type(self):
        return 'wl_display' if self.name == 'wl_display' else 'wl_proxy'

    def _render_forward_decls(self):
        # Write the forward declarations required for this class
        tys = [self.cpp_name]
        for req in self.requests:
            tys.extend(req.referenced_types())
        for e in self.events:
            tys.extend(e.referenced_types())
        return '\n'.join('class {};'.format(t) for t in tys)

    def _render_request_decls(self, indent):
        return '\n'.join(r.render_decl(indent) for r in self.requests)

    def write_impl(self, odir):
        opath = self.impl_path(odir)
        if not path.isdir(path.dirname(opath)):
            os.makedirs(path.dirname(opath))

        content = '''\
            #include "${cpp_name}.hpp"

            $includes

            #include <wayland-client-core.h>

            using namespace wl;

            $wl_interface_spec

            $specials_impl

            $cpp_name::$cpp_name(::$impl_type*&& impl) : _impl(impl) {
                impl = nullptr;
                if (_impl) {
                    static void (*listeners[])() = {
                        $event_listeners
                    };
                    ::wl_proxy_add_listener(
                        reinterpret_cast<::wl_proxy*>(_impl),
                        listeners,
                        this
                    );
                }
            }

            $cpp_name::$cpp_name($cpp_name&& other) {
                *this = std::move(other);
            }

            $cpp_name& $cpp_name::operator=($cpp_name&& other) {
                auto tmp = other._impl;
                other._impl = _impl;
                _impl = tmp;
                if (_impl) {
                    ::wl_proxy_set_user_data(reinterpret_cast<::wl_proxy*>(_impl), this);
                }
                if (other._impl) {
                    ::wl_proxy_set_user_data(reinterpret_cast<::wl_proxy*>(other._impl), &other);
                }
                return *this;
            }

            $cpp_name::~$cpp_name() {
                if (_impl) {
                    ::$destroyer(_impl);
                }
                _impl = nullptr;
            }

            $req_impls
        '''
        listeners = ', '.join(e.event_listener(12) for e in self.events)
        content = render_block(
            content,
            cpp_name=self.cpp_name,
            destroyer=self.destroyer,
            impl_type=self.impl_type,
            includes=self._render_includes(include_soft=True),
            wl_interface_spec=self._render_wl_interface_spec(),
            event_listeners=listeners,
            req_impls=self._render_request_impls(),
            specials_impl=render_block(_specials_for(self.cpp_name)['impls']))
        write_if_different(opath, content)

    @property
    def destroyer(self):
        return 'wl_display_disconnect' if self.name == 'wl_display' else 'wl_proxy_destroy'

    def _render_wl_interface_spec(self):
        messages = '\n'.join(r.render_wl_message() for r in self.requests)
        events = '\n'.join(e.render_wl_message() for e in self.events)
        methods_array = ', '.join('_{}_message'.format(r.name)
                                  for r in self.requests)
        events_array = ', '.join('_{}_message'.format(e.name)
                                 for e in self.events)
        interface = render_block(
            '''\
            const ::wl_message _${iface_name}_methods[] = { $methods_array };
            const ::wl_message _${iface_name}_events[] = { $events_array };
            ::wl_interface wl::detail::${iface_name} = {
                "$name",
                $version,
                $n_methods,
                _${iface_name}_methods,
                $n_events,
                _${iface_name}_events,
            };
            ''',
            iface_name=self.interface_name,
            name=self.name,
            version=self.version,
            n_methods=len(self.requests),
            methods_array=methods_array,
            n_events=len(self.events),
            events_array=events_array)
        return render_block(
            '''\
                namespace {
                $wl_messages
                }
                $wl_interface
            ''',
            iface_name=self.interface_name,
            wl_messages=messages + '\n' + events,
            wl_interface=interface)

    def _render_request_impls(self):
        return '\n'.join(r.render_impl() for r in self.requests)

    def _render_includes(self, include_soft=False):
        tys = []
        for req in self.requests:
            tys.extend(req.referenced_types(include_soft=include_soft))
        for e in self.events:
            tys.extend(e.referenced_types(include_soft=include_soft))
        return '\n'.join('#include "{tn}.hpp"'.format(tn=tn) for tn in tys)

    def _render_enums(self, indent=0):
        return ''.join(e.render(indent + 4) for e in self.enums)


def _specials_for(name):
    return {
        'display': {
            'decls': '''
                static display connect(const string& arg, error_code&);
                static display connect(const string& arg = {}) {
                    error_code ec;
                    auto disp = connect(arg, ec);
                    detail::ec_check(ec, "wl::display::connect()");
                    return std::move(disp);
                }
                static display connect(error_code& ec) {
                    return connect("", ec);
                }

                int get_fd() const;

                int roundtrip(error_code&) noexcept;
                int roundtrip() {
                    std::error_code ec;
                    auto count = roundtrip(ec);
                    detail::ec_check(ec, "wl::display::roundtrip()");
                    return count;
                }

                int flush(error_code&) noexcept;
                int flush() {
                    std::error_code ec;
                    auto count = flush(ec);
                    detail::ec_check(ec, "wl::display::flush()");
                    return count;
                }

                void prepare_read(error_code& ec) noexcept;
                void prepare_read() {
                    error_code ec;
                    prepare_read(ec);
                    detail::ec_check(ec, "wl::display::prepare_read()");
                }

                void cancel_read(error_code& ec) noexcept;
                void cancel_read() {
                    error_code ec;
                    cancel_read(ec);
                    detail::ec_check(ec, "wl::display::cancel_read()");
                }

                int read_events(error_code& ec) noexcept;
                int read_events() {
                    error_code ec;
                    auto count = read_events(ec);
                    detail::ec_check(ec, "wl::display::read_events()");
                    return count;
                }

                int dispatch_pending(error_code& ec) noexcept;
                int dispatch_pending() {
                    error_code ec;
                    auto count = dispatch_pending(ec);
                    detail::ec_check(ec, "wl::display::dispatch_pending()");
                    return count;
                }

                template <typename Func>
                decltype(auto) autoflush(Func&& fn) {
                    try {
                        decltype(auto) ret = std::forward<Func>(fn)();
                        flush();
                        return std::forward<decltype(ret)>(ret);
                    } catch (...) {
                        error_code ignored;
                        flush(ignored);
                        throw;
                    }
                }
            ''',
            'impls': '''
                display display::connect(const string& arg, error_code& ec) {
                    auto ptr = detail::call(::wl_display_connect, ec, arg.empty() ? nullptr : arg.data());
                    return display{std::move(ptr)};
                }

                int display::get_fd() const {
                    return ::wl_display_get_fd(_impl);
                }

                int display::flush(std::error_code& ec) noexcept {
                    return detail::call(::wl_display_flush, ec, get());
                }

                int display::roundtrip(std::error_code& ec) noexcept {
                    return detail::call(::wl_display_roundtrip, ec, get());
                }

                void display::prepare_read(error_code& ec) noexcept {
                    detail::call(::wl_display_prepare_read, ec, _impl);
                }

                void display::cancel_read(error_code& ec) noexcept {
                    errno = 0;
                    ::wl_display_cancel_read(_impl);
                    ec = detail::ec_from_errno();
                }

                int display::read_events(error_code& ec) noexcept {
                    return detail::call(::wl_display_read_events, ec, _impl);
                }

                int display::dispatch_pending(error_code& ec) noexcept {
                    return detail::call(::wl_display_dispatch_pending, ec, _impl);
                }
            ''',
        },
        'registry': {
            'decls': '''
                private:
                ::wl_proxy* _bind(std::uint32_t id, std::uint32_t version, ::wl_interface&);

                public:
                template <typename T>
                T bind(std::uint32_t id, std::uint32_t version) {
                    auto ret = T(_bind(id, version, T::interface));
                    auto ec = detail::ec_from_errno();
                    detail::ec_check(ec, "wl::registry::bind()");
                    return std::move(ret);
                }
            ''',
            'impls': '''
                ::wl_proxy* registry::_bind(std::uint32_t id, std::uint32_t version, ::wl_interface& interface) {
                    auto ret = ::wl_proxy_marshal_constructor_versioned(_impl, 0, &interface, version, id, interface.name, version, nullptr);
                    if (ret == nullptr) {
                        detail::ec_check(detail::ec_from_errno(), "wl::registry::bind()");
                        std::terminate();
                    }
                    return ret;
                }
            ''',
        }
    }.get(name, {'decls': '',
                 'impls': ''})


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--xml', help='Path to XML file', required=True)
    parser.add_argument(
        '--out', help='Root directory for generated files', required=True)
    parser.add_argument(
        '--list',
        help='Just list files to generate, don\'t generate them',
        action='store_true')
    args = parser.parse_args(argv)

    tree = ElementTree.parse(args.xml)
    root = tree.getroot()
    proto = list(root.iter('protocol'))[0]

    types = [Interface(n) for n in proto.iter('interface')]
    odir = path.join(args.out, 'wl')
    for t in types:
        if args.list:
            t.print_output_files(odir)
        else:
            t.write_files(odir)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
