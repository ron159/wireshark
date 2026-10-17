/* column_test.c
 * Custom-column runtime binding and preference regression tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#undef G_DISABLE_ASSERT

#include <glib.h>
#include <string.h>

#include <epan/column.h>
#include <epan/column-info.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/prefs.h>
#include <epan/register.h>
#include <ui/failure_message.h>
#include <wiretap/wtap.h>
#include <wsutil/filesystem.h>
#include <wsutil/value_string.h>
#include <wsutil/wslog.h>

static int proto_column_test;
static int hf_value = -1;
static int hf_text = -1;
static int hf_none = -1;
static int hf_missing = -1;

static const char *column_formats[] = {
    "Fixed", "%Cus:column_test.value:0:D",
    "Dynamic", "%Cus::0:DF"
};

static void
register_test_protocol(register_cb cb, void *client_data)
{
    static const value_string values[] = {
        { 7, "Seven" },
        { 9, "Nine" },
        { 0, NULL }
    };
    static hf_register_info fields[] = {
        { &hf_value, { "Value", "column_test.value", FT_UINT16, BASE_DEC,
            VALS(values), 0, NULL, HFILL } },
        { &hf_text, { "Text", "column_test.text", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL } },
        { &hf_none, { "Present", "column_test.present", FT_NONE, BASE_NONE,
            NULL, 0, NULL, HFILL } },
        { &hf_missing, { "Missing", "column_test.missing", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL } }
    };

    register_all_protocols(cb, client_data);
    proto_column_test = proto_register_protocol("Column binding test", "Column Test", "column_test");
    proto_register_field_array(proto_column_test, fields, G_N_ELEMENTS(fields));
}

static pref_t *
column_format_preference(void)
{
    pref_t *pref = prefs_find_preference(prefs_find_module("gui"), "column.format");
    g_assert_nonnull(pref);
    return pref;
}

static void
set_column_preferences(const char *value)
{
    char *argument = g_strconcat("gui.column.format:", value, NULL);
    char *error = NULL;
    prefs_set_pref_e result = prefs_set_pref(argument, &error);
    g_assert_cmpint(result, ==, PREFS_SET_OK);
    g_assert_null(error);
    g_free(argument);
}

static epan_dissect_t *
create_test_tree(column_info *cinfo)
{
    static const uint8_t bytes[] = { 0, 7, 0, 9 };
    /* col_init is internal; initialize both columns through the public API. */
    col_set_writable(cinfo, -1, true);
    col_set_writable(cinfo, COL_CUSTOM, true);
    col_clear(cinfo, COL_CUSTOM);
    epan_dissect_t *edt = epan_dissect_new(NULL, true, true);
    edt->pi.cinfo = cinfo;
    edt->tvb = tvb_new_real_data(bytes, sizeof(bytes), sizeof(bytes));
    col_custom_prime_edt(edt, cinfo);
    proto_tree_add_protocol_format(edt->tree, proto_column_test, edt->tvb, 0,
        sizeof(bytes), "Column test protocol");
    proto_tree_add_uint_format_value(edt->tree, hf_value, edt->tvb, 0, 2, 7, "first sample");
    proto_tree_add_uint_format_value(edt->tree, hf_value, edt->tvb, 2, 2, 9, "second sample");
    proto_tree_add_none_format(edt->tree, hf_none, edt->tvb, 0, 0, "Present marker");
    return edt;
}

static void
test_runtime_atomic_failure(void)
{
    column_info cinfo = { 0 };
    build_column_format_array(&cinfo, prefs.num_cols, true);
    g_assert_true(col_custom_set_fields(&cinfo, 1, "column_test.value", -1));
    col_item_t *item = &cinfo.columns[1];
    char *fields = item->col_custom_fields;
    struct epan_dfilter *filter = item->col_custom_dfilter;
    GSList *field_ids = item->col_custom_fields_ids;
    item->col_data = "previous display";
    g_strlcpy(item->col_buf, "previous buffer", COL_MAX_LEN);
    cinfo.col_expr.col_expr[1] = "previous expression";
    g_strlcpy(cinfo.col_expr.col_expr_val[1], "previous value", COL_MAX_LEN);
    item->col_fence = 3;

    const char *invalid[] = { "column_test.value ==", "column_test.unknown" };
    for (unsigned i = 0; i < G_N_ELEMENTS(invalid); i++) {
        g_assert_false(col_custom_set_fields(&cinfo, 1, invalid[i], 2));
        g_assert_true(item->col_custom_fields == fields);
        g_assert_true(item->col_custom_dfilter == filter);
        g_assert_true(item->col_custom_fields_ids == field_ids);
        g_assert_cmpint(item->col_custom_occurrence, ==, -1);
        g_assert_cmpstr(item->col_data, ==, "previous display");
        g_assert_cmpstr(item->col_buf, ==, "previous buffer");
        g_assert_cmpstr(cinfo.col_expr.col_expr[1], ==, "previous expression");
        g_assert_cmpstr(cinfo.col_expr.col_expr_val[1], ==, "previous value");
        g_assert_cmpint(item->col_fence, ==, 3);
    }
    /* Quoted 'or' is split by the existing column regex. Preserve the
     * ordinary custom-column behavior, which keeps the usable field. */
    g_assert_true(col_custom_set_fields(&cinfo, 1,
        "column_test.value || column_test.text == \"a or b\"", 0));
    g_assert_nonnull(item->col_custom_fields_ids);
    g_assert_cmpint(((col_custom_t *)item->col_custom_fields_ids->data)->field_id, ==, hf_value);
    g_assert_false(col_custom_set_fields(NULL, 0, "column_test.value", 0));
    g_assert_false(col_custom_set_fields(&cinfo, -1, "column_test.value", 0));
    g_assert_false(col_custom_set_fields(&cinfo, cinfo.num_cols, "column_test.value", 0));
    item->col_fmt = COL_NUMBER;
    g_assert_false(col_custom_set_fields(&cinfo, 1, "column_test.value", 0));
    item->col_fmt = COL_CUSTOM;
    col_cleanup(&cinfo);
}

static void
test_runtime_clear(void)
{
    column_info cinfo = { 0 };
    build_column_format_array(&cinfo, prefs.num_cols, true);
    g_assert_null(cinfo.columns[1].col_custom_fields);
    const char *empty[] = { "", NULL };
    for (unsigned i = 0; i < G_N_ELEMENTS(empty); i++) {
        g_assert_true(col_custom_set_fields(&cinfo, 1, "column_test.value", 2));
        col_item_t *item = &cinfo.columns[1];
        item->col_data = "stale display";
        g_strlcpy(item->col_buf, "stale buffer", COL_MAX_LEN);
        g_strlcpy(cinfo.col_expr.col_expr_val[1], "stale value", COL_MAX_LEN);
        item->col_fence = 4;
        g_assert_true(col_custom_set_fields(&cinfo, 1, empty[i], -1));
        g_assert_null(item->col_custom_fields);
        g_assert_null(item->col_custom_dfilter);
        g_assert_null(item->col_custom_fields_ids);
        g_assert_null(item->col_data);
        g_assert_cmpint(item->col_custom_occurrence, ==, 0);
        g_assert_cmpint(item->col_fence, ==, 0);
        g_assert_cmpstr(item->col_buf, ==, "");
        g_assert_cmpstr(cinfo.col_expr.col_expr[1], ==, "");
        g_assert_cmpstr(cinfo.col_expr.col_expr_val[1], ==, "");
    }
    col_cleanup(&cinfo);
}

static void
test_runtime_display(void)
{
    const char displays[] = { COLUMN_DISPLAY_VALUES, COLUMN_DISPLAY_STRINGS, COLUMN_DISPLAY_DETAILS };
    const int occurrences[] = { 0, 1, -1 };
    for (unsigned mode = 0; mode < G_N_ELEMENTS(displays); mode++) {
        for (unsigned occurrence = 0; occurrence < G_N_ELEMENTS(occurrences); occurrence++) {
            set_column_display_format(0, displays[mode]);
            set_column_display_format(1, displays[mode]);
            set_column_custom_occurrence(0, occurrences[occurrence]);
            column_info cinfo = { 0 };
            build_column_format_array(&cinfo, prefs.num_cols, true);
            g_assert_true(col_custom_set_fields(&cinfo, 1, "column_test.value", occurrences[occurrence]));
            epan_dissect_t *edt = create_test_tree(&cinfo);
            epan_dissect_fill_in_columns(edt, false, false);
            const char *fixed = get_column_text(&cinfo, 0);
            const char *dynamic = get_column_text(&cinfo, 1);
            g_assert_cmpstr(dynamic, ==, fixed);
            g_assert_nonnull(dynamic);
            g_assert_cmpstr(dynamic, !=, "");
            if (displays[mode] == COLUMN_DISPLAY_VALUES) {
                const char *expected[] = { "7,9", "7", "9" };
                g_assert_cmpstr(dynamic, ==, expected[occurrence]);
            } else if (displays[mode] == COLUMN_DISPLAY_DETAILS) {
                const char *expected[] = { "first sample,second sample", "first sample", "second sample" };
                g_assert_cmpstr(dynamic, ==, expected[occurrence]);
            }
            epan_dissect_free(edt);
            col_cleanup(&cinfo);
        }
    }
    set_column_display_format(0, COLUMN_DISPLAY_DETAILS);
    set_column_display_format(1, COLUMN_DISPLAY_DETAILS);
    set_column_custom_occurrence(0, 0);
}

static void
test_runtime_nonvalue_and_missing(void)
{
    const char *fields[] = { "column_test", "column_test.present", "column_test.missing" };
    for (unsigned i = 0; i < G_N_ELEMENTS(fields); i++) {
        set_column_custom_fields(0, fields[i]);
        column_info cinfo = { 0 };
        build_column_format_array(&cinfo, prefs.num_cols, true);
        g_assert_true(col_custom_set_fields(&cinfo, 1, fields[i], 0));
        epan_dissect_t *edt = create_test_tree(&cinfo);
        epan_dissect_fill_in_columns(edt, false, false);
        g_assert_cmpstr(get_column_text(&cinfo, 1), ==, get_column_text(&cinfo, 0));
        if (i < 2) {
            g_assert_cmpstr(get_column_text(&cinfo, 1), !=, "");
        } else {
            g_assert_cmpstr(get_column_text(&cinfo, 1), ==, "");
        }
        epan_dissect_free(edt);
        col_cleanup(&cinfo);
    }
    set_column_custom_fields(0, "column_test.value");
}

static void
test_preference_roundtrip(void)
{
    char *saved = prefs_pref_to_str(column_format_preference(), pref_current);
    set_column_preferences("\"Dynamic\",\"%Cus:column_test.value:-1:UF\","
        "\"Fixed\",\"%Cus:column_test.text[0:2]:2:D\"");
    g_assert_true(get_column_custom_dynamic(0));
    g_assert_cmpstr(get_column_custom_fields(0), ==, "");
    g_assert_cmpint(get_column_custom_occurrence(0), ==, -1);
    g_assert_cmpint(get_column_display_format(0), ==, COLUMN_DISPLAY_VALUES);
    g_assert_false(get_column_custom_dynamic(1));
    g_assert_cmpstr(get_column_custom_fields(1), ==, "column_test.text[0:2]");

    char *serialized = prefs_pref_to_str(column_format_preference(), pref_current);
    g_assert_nonnull(strstr(serialized, "%Cus::-1:UF"));
    g_assert_null(strstr(serialized, "column_test.value"));
    g_assert_nonnull(strstr(serialized, "%Cus:column_test.text[0:2]:2:D"));
    set_column_preferences(serialized);
    g_assert_true(get_column_custom_dynamic(0));
    g_assert_cmpstr(get_column_custom_fields(0), ==, "");
    g_assert_cmpstr(get_column_custom_fields(1), ==, "column_test.text[0:2]");
    g_free(serialized);
    set_column_preferences(saved);
    g_free(saved);
}

static void
test_preference_runtime_isolation(void)
{
    char *before = prefs_pref_to_str(column_format_preference(), pref_current);
    column_info cinfo = { 0 };
    build_column_format_array(&cinfo, prefs.num_cols, true);
    g_assert_true(cinfo.columns[1].col_custom_dynamic);
    g_assert_null(cinfo.columns[1].col_custom_fields);
    g_assert_true(col_custom_set_fields(&cinfo, 1, "column_test.text", -1));
    g_assert_cmpstr(get_column_custom_fields(1), ==, "");
    g_assert_cmpint(get_column_custom_occurrence(1), ==, 0);
    char *after = prefs_pref_to_str(column_format_preference(), pref_current);
    g_assert_cmpstr(after, ==, before);
    column_info reopened = { 0 };
    build_column_format_array(&reopened, prefs.num_cols, true);
    g_assert_true(reopened.columns[1].col_custom_dynamic);
    g_assert_null(reopened.columns[1].col_custom_fields);
    col_cleanup(&reopened);
    col_cleanup(&cinfo);
    g_free(after);
    g_free(before);
}

int
main(int argc, char **argv)
{
    g_set_prgname("column_test");
    ws_log_init(NULL, "Column Tests");
    g_test_init(&argc, &argv, NULL);
    char *error = configuration_init(argv[0], "wireshark");
    g_assert_null(error);
    init_report_failure_message("column_test");
    wtap_init(false, "WIRESHARK", NULL, 0);
    epan_app_data_t app_data = { 0 };
    app_data.env_var_prefix = "WIRESHARK";
    app_data.col_fmt = column_formats;
    app_data.num_cols = 2;
    app_data.register_func = register_test_protocol;
    app_data.handoff_func = register_all_protocol_handoffs;
    g_assert_true(epan_init(NULL, NULL, false, &app_data));

    g_test_add_func("/column/runtime/atomic_failure", test_runtime_atomic_failure);
    g_test_add_func("/column/runtime/clear", test_runtime_clear);
    g_test_add_func("/column/runtime/display", test_runtime_display);
    g_test_add_func("/column/runtime/nonvalue_and_missing", test_runtime_nonvalue_and_missing);
    g_test_add_func("/column/preferences/roundtrip", test_preference_roundtrip);
    g_test_add_func("/column/preferences/runtime_isolation", test_preference_runtime_isolation);
    int result = g_test_run();
    epan_cleanup();
    wtap_cleanup();
    return result;
}
