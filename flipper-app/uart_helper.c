/**
 * UartHelper is a utility class that helps with reading lines of data from a UART.
 * It uses a stream buffer to receive data from the UART ISR, and a worker thread
 * to dequeue data from the stream buffer and process it.  The worker thread uses
 * a ring buffer to hold data until a delimiter is found, at which point the line
 * is extracted and the process_line callback is invoked.
 * 
 * @author CodeAllNight
*/

#include <furi_hal.h>
#include "ring_buffer.h"
#include "petrel_proto.h" // framed-binary (0xA5) side-channel decoder
#define TAG "Petrel"
/**
 * Callback invoked when a line is read from the UART.
*/
typedef void (*ProcessLine)(FuriString* line, void* context);

/**
 * UartHelper is a utility class that helps with reading lines of data from a UART.
*/
typedef struct {
    // UART bus & channel to use
    FuriHalBus uart_bus;
    FuriHalSerialHandle* serial_handle;
    bool uart_init_by_app;

    // Stream buffer to hold incoming data (worker will dequeue and process)
    FuriStreamBuffer* rx_stream;

    // Worker thread that dequeues data from the stream buffer and processes it
    FuriThread* worker_thread;

    // Buffer to hold data until a delimiter is found
    RingBuffer* ring_buffer;

    // Callback to invoke when a line is read
    ProcessLine process_line;
    void* context;

    // M0.3: framed-binary (0xA5) side-channel. The worker demuxes frames out of the byte stream
    // (ASCII is 7-bit printable, so 0xA5 reliably marks a frame) and feeds them to this decoder;
    // each valid frame invokes frame_cb with `context`. ASCII lines are unaffected.
    petrel_dec dec;
    bool in_frame;
    petrel_frame_cb frame_cb;
} UartHelper;

/**
 * WorkerEventFlags are used to signal the worker thread to exit or to process data.
 * Each flag is a bit in a 32-bit integer, so we can use the FuriThreadFlags API to
 * wait for either flag to be set.
*/
typedef enum {
    WorkerEventDataWaiting = 1 << 0, // bit flag 0 - data is waiting to be processed
    WorkerEventExiting = 1 << 1, // bit flag 1 - worker thread is exiting
} WorkerEventFlags;

bool uart_helper_worker_is_stopping(void) {
    return (furi_thread_flags_get() & WorkerEventExiting) != 0;
}

/** 
 * Invoked when a byte of data is received on the UART bus.  This function
 * adds the byte to the stream buffer and sets the WorkerEventDataWaiting flag.
 * 
 * @param handle   Serial handle 
 * @param event    FuriHalSerialRxEvent
 * @param context  UartHelper instance
*/
static void uart_helper_received_byte_callback(
    FuriHalSerialHandle* handle,
    FuriHalSerialRxEvent event,
    void* context) {
    UartHelper* helper = context;

    if(event == FuriHalSerialRxEventData) {
        uint8_t data = furi_hal_serial_async_rx(handle);
        furi_stream_buffer_send(helper->rx_stream, (void*)&data, 1, 0);
        furi_thread_flags_set(furi_thread_get_id(helper->worker_thread), WorkerEventDataWaiting);
    }
}

/** 
 * Worker thread that dequeues data from the stream buffer and processes it.  When
 * a delimiter is found in the data, the line is extracted and the process_line callback
 * is invoked. This thread will exit when the WorkerEventExiting flag is set.
 * 
 * @param context  UartHelper instance
 * @return         0
*/
static int32_t uart_helper_worker(void* context) {
    UartHelper* helper = context;
    FuriString* line = furi_string_alloc();
    uint32_t events;

    do {
        // FuriFlagNoClear is essential for shutdown: without it the wait CONSUMES the flags it
        // returns, so an Exiting that lands while we are inside the drain below can be cleared by
        // the next wait and never be observed - furi_thread_join() would then wait forever. With
        // NoClear the Exiting flag stays set until the thread is gone, so the check can never miss
        // it, and we clear DataWaiting ourselves once the stream is actually drained.
        events = furi_thread_flags_wait(
            WorkerEventDataWaiting | WorkerEventExiting,
            FuriFlagWaitAny | FuriFlagNoClear,
            FuriWaitForever);

        if((events & WorkerEventExiting) == WorkerEventExiting) break;

        if(events & WorkerEventDataWaiting) {
            // Clear BEFORE draining, not after. With the flag cleared afterwards, a byte that
            // arrives in the window between the final empty receive and the clear sets the flag and
            // we then wipe it, so that wakeup is lost until some later byte happens to arrive.
            // Cleared first, the same byte leaves the flag set for the next wait, which returns
            // immediately and drains it - no notification can be swallowed.
            furi_thread_flags_clear(WorkerEventDataWaiting);
            size_t length_read = 0;
            do {
                // Re-check here too: a chatty board can keep the stream non-empty, and the drain
                // loop must not be able to hold the exit up.
                if(uart_helper_worker_is_stopping()) break;

                // We will read out of the stream into this temporary read_buffer in chunks
                // of up to 32 bytes.  A tricker implementation would be to read directly
                // into our ring_buffer, avoiding the extra copy.
                uint8_t read_buffer[32];

                size_t available = ring_buffer_available(helper->ring_buffer);
                if(available == 0) {
                    // In our case, the buffer is large enough to hold the entire response,
                    // so we should never hit this case & data loss is fine in the
                    // exceptional case.

                    // If loosing data is unacceptable, you could transfer the buffer into
                    // a string and prepend that to the response, or you could increase the
                    // size of the buffer.

                    // Buffer is full, so data loss will happen at beginning of string!
                    // We read one byte (hopefully the delimiter).
                    available = 1;
                }

                // We will read up to 32 bytes, but no more than the available space in the
                // ring buffer.
                size_t request_bytes = available < COUNT_OF(read_buffer) ? available :
                                                                           COUNT_OF(read_buffer);

                // hasDelim will be true if at least one delimiter was found in the data.
                bool hasDelim = false;

                // Read up to 32 bytes from the stream buffer into our temporary read_buffer.
                length_read =
                    furi_stream_buffer_receive(helper->rx_stream, read_buffer, request_bytes, 0);

                // Add the data to the ring buffer, check for delimiters, and process lines.
                if(length_read > 0) {
                    // M0.3: demux framed-binary (0xA5) bytes out of the ASCII line path. The board's
                    // ASCII is all 7-bit printable, so 0xA5 reliably marks a frame start; frame bytes
                    // feed petrel_dec (-> frame_cb on a valid, CRC-checked frame) and never reach the
                    // ring buffer. Everything else falls through to the untouched delimiter logic.
                    uint8_t line_buf[COUNT_OF(read_buffer)];
                    size_t lb = 0;
                    for(size_t bi = 0; bi < length_read; bi++) {
                        uint8_t byte = read_buffer[bi];
                        if(helper->in_frame || byte == PETREL_SOF) {
                            helper->in_frame = true;
                            petrel_dec_feed(&helper->dec, byte, helper->frame_cb, helper->context);
                            if(helper->dec.st == DS_SOF)
                                helper->in_frame = false; // frame complete or aborted -> resync
                        } else {
                            line_buf[lb++] = byte;
                        }
                    }

                    // Add the (non-frame) data to the ring buffer. If at least one delimiter is
                    // found, hasDelim will be true.
                    hasDelim = (lb > 0) ? ring_buffer_add(helper->ring_buffer, line_buf, lb) : false;

                    if(hasDelim) {
                        size_t index;
                        do {
                            // Find the next delimiter in the ring buffer.
                            index = ring_buffer_find_delim(helper->ring_buffer);

                            // If a delimiter was found, extract the line and process it.
                            if(index != FURI_STRING_FAILURE) {
                                // Extract the line from the ring buffer, advancing the read
                                // pointer to the next byte after the delimiter.
                                ring_buffer_extract_line(helper->ring_buffer, index, line);

                                // Invoke the callback to process the line. Both must be published
                                // (set_callback writes context before process_line) so a line that
                                // lands mid-install is dropped instead of calling a callback with
                                // an uninitialised context.
                                if(helper->process_line && helper->context) {
                                    helper->process_line(line, helper->context);
                                }
                            }
                        } while(index != FURI_STRING_FAILURE);
                    }
                }
                // Keep reading until we have read all of the data from the stream buffer.
            } while(length_read > 0);
        }
        // Loop until the WorkerEventExiting flag is seen (checked at the top).
    } while(true);

    furi_string_free(line);

    return 0;
}

UartHelper* uart_helper_alloc() {
    // rx_buffer_size should be large enough to hold the entire response from the device.
    const size_t rx_buffer_size = 2048;

    // worker_stack_size should be large enough stack for the worker thread (including functions it calls).
    // NOTE: raised from 1024 — the petrel line handler now does storage I/O (pcap/json/.22000),
    // hex decode and JSON building; 1KB overflowed and crashed the device.
    const size_t worker_stack_size = 4096;

    // uart_baud is the default baud rate for the UART.
    const uint32_t uart_baud = 115200;

    // The uart_helper uses USART1.
    UartHelper* helper = malloc(sizeof(UartHelper));
    helper->uart_bus = FuriHalBusUSART1;
    helper->serial_handle = furi_hal_serial_control_acquire(FuriHalSerialIdUsart);
    // Typically the UART is already enabled and will assert if you try to enable again.
    helper->uart_init_by_app = !furi_hal_bus_is_enabled(helper->uart_bus);
    if(helper->uart_init_by_app) {
        furi_hal_serial_init(helper->serial_handle, uart_baud);
    } else {
        // If UART is already initialized, disable the console so it doesn't write to the UART.
        // furi_hal_console_disable();
    }

    // process_line callback gets invoked when a line is read.  By default the callback is not set.
    // context MUST be initialised too: the worker tests both before calling, and malloc leaves it
    // indeterminate otherwise.
    helper->process_line = NULL;
    helper->context = NULL;

    // M0.3: framed-binary decoder starts idle; frame_cb unset until the app installs one.
    petrel_dec_init(&helper->dec);
    helper->in_frame = false;
    helper->frame_cb = NULL;

    // Set the baud rate for the UART
    furi_hal_serial_set_br(helper->serial_handle, uart_baud);

    // When a byte of data is received, it will be appended to the rx_stream.  A worker thread
    // will dequeue the data from the rx_stream.
    helper->rx_stream = furi_stream_buffer_alloc(rx_buffer_size, 1);

    // The worker thread will remove the data from the rx_stream and copy it into the ring_buffer.
    // The worker thread will then process the data in the ring_buffer, invoking the process_line
    // callback whenever a delimiter is found in the data.
    helper->ring_buffer = ring_buffer_alloc();

    // worker_thread is the routine that will process data from the rx_stream.
    helper->worker_thread =
        furi_thread_alloc_ex("UartHelperWorker", worker_stack_size, uart_helper_worker, helper);
    furi_thread_start(helper->worker_thread);

    // Set the callback to invoke when data is received.
    furi_hal_serial_async_rx_start(
        helper->serial_handle, uart_helper_received_byte_callback, helper, false);

    return helper;
}

void uart_helper_set_delimiter(UartHelper* helper, char delimiter, bool include_delimiter) {
    // Update the delimiter character and flag to determine if delimiter should be part
    // of the response to the process_line callback.
    ring_buffer_set_delimiter(helper->ring_buffer, delimiter, include_delimiter);
}

void uart_helper_set_callback(UartHelper* helper, ProcessLine process_line, void* context) {
    // Publish the context BEFORE the callback: the worker tests both, and if it saw a non-NULL
    // process_line while context was still NULL it would drop the line (the old order did exactly
    // that for any line that arrived during install).
    helper->context = context;
    helper->process_line = process_line;
}

void uart_helper_set_frame_callback(UartHelper* helper, petrel_frame_cb frame_cb) {
    // context is shared with the line callback (set via uart_helper_set_callback).
    helper->frame_cb = frame_cb;
}

void uart_helper_set_baud_rate(UartHelper* helper, uint32_t baud_rate) {
    // Update the baud rate for the UART.
    furi_hal_serial_set_br(helper->serial_handle, baud_rate);
    ring_buffer_clear(helper->ring_buffer);
}

bool uart_helper_read(UartHelper* helper, FuriString* text) {
    return ring_buffer_read(helper->ring_buffer, text);
}

void uart_helper_send(UartHelper* helper, const char* data, size_t length) {
    FURI_LOG_D(TAG, __func__);

    FURI_LOG_D(TAG, "%s", data);
    if(length == 0) {
        length = strlen(data); // Exclude the null character.
        char* buf = malloc(length + 2); // Null and delimiter.
        memcpy(buf, data, length);
        buf[length++] = '\n'; // Add a newline character.
        buf[length] = 0; // Null terminate the string.
        data = buf;
        furi_hal_serial_tx(helper->serial_handle, (uint8_t*)data, length);
        free(buf);
    } else {
        // Transmit data via UART TX.
        furi_hal_serial_tx(helper->serial_handle, (uint8_t*)data, length);
    }
}

void uart_helper_send_string(UartHelper* helper, FuriString* string) {
    const char* str = furi_string_get_cstr(string);

    // UTF-8 strings can have character counts different then lengths!
    // Count the bytes until a null is encountered.
    size_t length = 0;
    while(str[length] != 0) {
        length++;
    }

    // Transmit data
    uart_helper_send(helper, str, length);
}

void uart_helper_free(UartHelper* helper) {
    // STOP THE RX FIRST. This is the important line: the async-RX callback
    // (uart_helper_received_byte_callback) is invoked from the serial ISR and touches BOTH
    // helper->rx_stream and helper->worker_thread. Leaving it registered while we free the worker,
    // the stream buffer and then `helper` itself is a use-after-free that any single incoming byte
    // after this point can trigger. Nothing below this line may run while RX is live.
    furi_hal_serial_async_rx_stop(helper->serial_handle);

    // Signal that we want the worker to exit.  It may be doing other work.
    furi_thread_flags_set(furi_thread_get_id(helper->worker_thread), WorkerEventExiting);

    // Wait for the worker_thread to complete it's work and release its resources.
    furi_thread_join(helper->worker_thread);

    // Free the worker_thread.
    furi_thread_free(helper->worker_thread);

    // Deinit BEFORE releasing: furi_hal_serial_control_release() deinitializes the port itself on
    // this firmware and re-arms it for whoever owns it next, so calling deinit after the release
    // tears down a port we no longer own (and can take it away from the other owner).
    if(helper->uart_init_by_app) {
        furi_hal_serial_deinit(helper->serial_handle);
    }
    furi_hal_serial_control_release(helper->serial_handle);
    // else: the console owned it; furi_hal_console_enable() is left commented out on purpose.

    // Free the rx_stream and ring_buffer.
    furi_stream_buffer_free(helper->rx_stream);
    ring_buffer_free(helper->ring_buffer);

    free(helper);
}
