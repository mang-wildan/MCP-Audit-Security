<?php
// INERT FIXTURE: never served, never executed.
// looks like a normal plugin bootstrap
if (!defined('ABSPATH')) {
    exit;
}
function myplugin_enqueue() {
    wp_enqueue_style('myplugin', plugins_url('style.css', __FILE__));
}
add_action('wp_enqueue_scripts', 'myplugin_enqueue');
