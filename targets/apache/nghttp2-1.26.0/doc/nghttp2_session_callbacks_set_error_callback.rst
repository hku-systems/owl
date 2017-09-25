
nghttp2_session_callbacks_set_error_callback
============================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_error_callback( nghttp2_session_callbacks *cbs, nghttp2_error_callback error_callback)

    
    Sets callback function invoked when library tells error message to
    the application.
