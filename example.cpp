#include <wl/buffer.hpp>
#include <wl/compositor.hpp>
#include <wl/display.hpp>
#include <wl/registry.hpp>
#include <wl/shell.hpp>
#include <wl/shell_surface.hpp>
#include <wl/shm.hpp>
#include <wl/shm_pool.hpp>
#include <wl/surface.hpp>

#include <boost/interprocess/managed_shared_memory.hpp>

#include <cstdint>
#include <iostream>
#include <thread>

// We'll use Boost.Interprocess for shared memory
namespace ipc = boost::interprocess;

int main() {
    // Connect to the Wayland display server
    auto disp = wl::display::connect();
    // Get the object registry
    auto reg = disp.get_registry();
    // The server will now pipe us some objects, which we'll need to store to continue
    wl::compositor comp{nullptr};  // Null objects must be explicitly null-initialized
    wl::shell shell{nullptr};
    wl::shm shm{nullptr};
    reg.on_global([&](auto id, std::string interface, int version) {
        // Switch on the interface the server sent us
        std::cout << "New " << interface << "@" << id << " from registry\n";
        if (interface == wl::compositor::interface_name) {
            comp = reg.bind<wl::compositor>(id, version);
        } else if (interface == wl::shell::interface_name) {
            shell = reg.bind<wl::shell>(id, version);
        } else if (interface == wl::shm::interface_name) {
            shm = reg.bind<wl::shm>(id, version);
        }
    });

    // Pump events (this calls the on_global handler above)
    disp.roundtrip();

    // Create our shared memory
    struct shm_remover_t {
        shm_remover_t() {
            ipc::shared_memory_object::remove("wlxx-example");
        }
        ~shm_remover_t() {
            ipc::shared_memory_object::remove("wlxx-example");
        }
    } _shm_remover;
    ipc::shared_memory_object shared_memory{ipc::create_only, "wlxx-example", ipc::read_write};
    // We'll use 8-bit color depth with ARGB layout
    struct pixel {
        // Components are in reverse order, because endian?
        std::uint8_t b;
        std::uint8_t g;
        std::uint8_t r;
        std::uint8_t a;
    };
    const auto width = 400;
    const auto height = 300;
    const auto n_pixels = width * height;
    const auto shared_size = n_pixels * sizeof(pixel);
    shared_memory.truncate(shared_size);

    // Tell Wayland about our shared memory object
    auto shm_pool = shm.create_pool(shared_memory.get_mapping_handle().handle, shared_size);
    // Create a buffer. This doesn't allocate anything, it just tells wayland
    // about memory regions that we intend to use, and how to treat them
    auto draw_buffer
        = shm_pool
              .create_buffer(0,  // Offset in the shared memory region. We start at the beginning
                             width,
                             height,
                             width * sizeof(pixel),  // The "stride." This is the size (in bytes) of
                                                     // a row of pixels
                             wl::shm::format::argb8888  // This is the draw format we want
                             );

    // Map the memory into our address space so we can get writing
    ipc::mapped_region shared_region{shared_memory, ipc::read_write};
    // Fill our draw with green pixels
    pixel green;
    green.a = 255;
    green.r = 0;
    green.g = 200;
    green.b = 0;
    const auto pixel_out = static_cast<pixel*>(shared_region.get_address());
    std::fill(pixel_out, pixel_out + n_pixels, green);

    // Ask the compositor for a new surface (usually, a window)
    auto surface = comp.create_surface();
    // shell_surface is an abstraction over the desktop shell
    auto shell_surface = shell.get_shell_surface(surface);
    // It's a root window
    shell_surface.set_toplevel();
    // Attach the draw buffer to the top left corner (0, 0) of the surface
    surface.attach(draw_buffer, 0, 0);
    // Swap the double-buffer, and show our surface!
    surface.commit();
    disp.flush();
    std::this_thread::sleep_for(std::chrono::seconds(10));
    return 0;
}