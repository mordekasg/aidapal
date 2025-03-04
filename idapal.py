import ida_kernwin
import ida_funcs
import idaapi
import idautils
import idc
import ida_hexrays
import ida_bytes
import ida_name
import ida_lines
import importlib.util
import threading
import json
import logging
from functools import partial

# this is the UI class that is used to display the results of the analysis
from idapal_qt_interface import *

# helper to extract information about the current target to inject into the context at runtime
from aidapal_helpers import context_juicer

dependencies_loaded = True
failed_dependency = ''
try:
    import requests
except ImportError as e:
    dependencies_loaded = False  # Set flag if a dependency fails
    failed_dependency = e.name  # Store the name of the missing dependency

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# OpenAPI service URL with endpoint
openapi_url = "http://localhost:1234/v1"
# this list holds the list of models registered with in OpenAPI
# you can get it manually from URL: http://localhost:1234/v1/models
models = [
    'bartowski/Qwen2.5-Coder-7B-Instruct-GGUF'
]

model_system_message = """You are an higly skilled expert at analyzing code that has been decompiled with IDA Hex Rays into IDA Hex Rays pseudocode. As a IDA Hex Rays pseudocode analyzer, you will be provided code that may or may not have symbols and variable names. You will analyze the IDA Hex Rays pseudocode and explain exactly what each line is doing. Then you will review your analysis and determine potential name for the function and variables within the function. Your task is to use your knowledge of reverse engineering, IDA Hex Rays pseudocode, C, C++ and Windows oprating system to assist the user with analysis and reverse engineering. Provide a detailed description of the IDA Hex Rays pseudocode to the user explaining what the code does, suggest a function name based on the analysis of the pseudocode, and new variable names based on the analysis of the code. Only respond with valid JSON using the keys 'function_name', 'comment' and an array 'variables'. Values should use plain ascii with no special characters. Use below JSON schema to generate output:
{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "function_name": {
      "type": "string"
    },
    "comment": {
      "type": "string"
    },
    "variables": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "original_name": {
            "type": "string"
          },
          "new_name": {
            "type": "string"
          },
          "description": {
            "type": "string"
          }
        },
        "required": [
          "original_name",
          "new_name",
          "description"
        ]
      }
    }
  },
  "required": [
    "function_name",
    "comment",
    "variables"
  ]
}

Analyze the following IDA Hex Rays pseudocode and generate a valid JSON string (based on JSON schema) containing the keys 'function_name', 'comment' and an array 'variables' (including original variable name, new variable name proposal and variable description) explaining what the code does, suggest a function name based on the analysis of the code, and new variable names based on the analysis of the code."""

aidapal_manual_juice = []


def do_analysis(code, model_name):
    url = openapi_url + "/chat/completions"
    headers = {"Content-Type": "application/json"}
    messages = [
        {"role": "system", "content": model_system_message},
        {"role": "user", "content": code}
    ]
    payload = {"model": model_name, "messages": messages, "stream": False}

    try:
        logging.info(f"Sending code to {model_name} model for analysis...")
        res = requests.post(url, headers=headers, json=payload)
        res.raise_for_status()
        t = res.json()['choices'][0]['message']['content'].replace("<|im_start|>", "").replace("```json", "").replace("```", "").strip()
        print(t)
        t = json.loads(t)
        logging.info("Successfully received analysis results.")
        return t
    except requests.exceptions.RequestException as e:
        logging.error(f"Request to {url} failed: {str(e)}")
    except ValueError as ve:
        logging.error(f"Failed to decode JSON response: {str(ve)}")
    except Exception as e:
        logging.error(f"Unexpected error during analysis: {str(e)}")
    return None


def aidapal_add_context(context_value):
    '''
    This function is used to manually add to the global context var aidapal_manual_juice
    '''
    aidapal_manual_juice.append(f"{context_value}")


def aidapal_get_context():
    '''
    print the current manual context
    '''
    outstr = ''
    for x in aidapal_manual_juice:
        outstr += f'{x}\n'
    return outstr


def do_show_ui(result, cur_func, data_address):
    aiDAPalUI(result, cur_func, data_address)
    return False


# examples/core/dump_selection.py
def get_hexrays_selection():
    '''
    get highlighted text from the hexrays view
    return None if no selection
    '''
    # dump current selection
    p0 = ida_kernwin.twinpos_t()
    p1 = ida_kernwin.twinpos_t()
    view = ida_kernwin.get_current_viewer()
    logging.debug(f'aiDAPal: getting hexrays selection')
    if ida_kernwin.read_selection(view, p0, p1):
        lines = get_widget_lines(view, p0, p1)
        logging.debug("\n".join(lines))
        return "\n".join(lines)
    return None


def get_widget_lines(widget, tp0, tp1):
    """
    get lines between places tp0 and tp1 in widget
    """
    ud = ida_kernwin.get_viewer_user_data(widget)
    lnar = ida_kernwin.linearray_t(ud)
    lnar.set_place(tp0.at)
    lines = []
    while True:
        cur_place = lnar.get_place()
        first_line_ref = ida_kernwin.l_compare2(cur_place, tp0.at, ud)
        last_line_ref = ida_kernwin.l_compare2(cur_place, tp1.at, ud)
        if last_line_ref > 0:  # beyond last line
            break
        line = ida_lines.tag_remove(lnar.down())
        if last_line_ref == 0:  # at last line
            line = line[0:tp1.x]
        elif first_line_ref == 0:  # at first line
            line = ' ' * tp0.x + line[tp0.x:]
        lines.append(line)
    return lines


def async_call(cur_func, model_name, extra_context=None, selected_code=None, data_address=None):
    # if we have a selection, get the selection, otherwise use the whole function
    logging.debug(f'aiDAPal: async call {model_name}')
    if selected_code:
        logging.debug('aiDAPal: selection')
        code = selected_code
    else:
        code = str(cur_func)
    logging.debug(f'aiDAPal: {code}')
    if extra_context:
        code = f'{extra_context}\n{code}'
    result = do_analysis(code, model_name)
    if result:
        call_do_show_ui = partial(do_show_ui, result, cur_func, data_address)
        # print(result)

        # update the function with the results
        ida_kernwin.execute_ui_requests([call_do_show_ui, ])


def get_data_references_query(target_data_ea):
    results = []
    query = ''
    target_data_name = ida_name.get_name(target_data_ea)
    # Ensure the decompiler is available
    if not ida_hexrays.init_hexrays_plugin():
        logging.error(f'aiDAPal: Hex-Rays decompiler is not available.')
        return results

    target_xrefs = []
    xrefs = idautils.XrefsTo(target_data_ea)
    for xref in xrefs:
        # get a reference to the function
        curfunc = ida_funcs.get_func_name(xref.frm)
        curfunc_t = ida_funcs.get_func(xref.frm)
        if curfunc:
            target_xrefs.append(curfunc_t.start_ea)

    # Iterate through all functions in the binary
    for ea in set(target_xrefs):
        func_name = ida_funcs.get_func_name(ea)

        try:
            # Decompile the function
            cfunc = ida_hexrays.decompile(ea)
            if not cfunc:
                logging.error(f'aiDAPal: failed to decompile function at {hex(ea)}')
                continue

            # Get the decompiled code as text
            decompiled_text = cfunc.get_pseudocode()
            # print(f'decompiled {hex(ea)}')
            # Search for the target function name in each line
            for line_number, line in enumerate(decompiled_text, 1):
                # Remove tags to get clean text
                line_text = ida_lines.tag_remove(line.line)

                if target_data_name in line_text:
                    # print(f'{target_func_name} - {line_text}')
                    results.append((func_name, line_number, line_text.strip()))

        except ida_hexrays.DecompilationFailure as e:
            logging.error(f'aiDAPal: decompilation failed for function at {hex(ea)}: {str(e)}')

    if results:
        query = f'/* {target_data_name} is referenced in the following locations:\n'
        # Build the query
        if results:
            for ref in results:
                query += f'in function {ref[0]}: {ref[2]}\n'
            query += f'*/\n{target_data_name}'
    return query


def get_function_data_ref_comments(current_func_ea):
    '''
    extracts string that is a c style comment block of comments for any data refs that
    have a comment
    '''
    if current_func_ea is not None:
        # Get references from the current function - returns a set of them
        # references = get_references_from_function(current_func_ea)
        logging.info(f'aiDAPal: gathering data references for {hex(current_func_ea)}')
        references = context_juicer.gather_unique_data_references(current_func_ea)
        # inject our manual defines into the comment block
        data_comments = f'/*{aidapal_get_context()}\n'
        for ref in references:
            data_comments += f'{ref}\n'
        data_comments += '*/'
        return data_comments
    else:
        logging.error(f'aiDAPal: no function at current address')
        return None


class FunctionDecompilerHandler(ida_kernwin.action_handler_t):
    model = ''
    selection = False

    def __init__(self, model, selection=False):
        self.model = model
        self.selection = selection
        logging.debug(f'aiDAPal: {model} {selection}')
        ida_kernwin.action_handler_t.__init__(self)

    # This method is called when the menu item is clicked
    def activate(self, ctx):
        # get the current function code
        cur_func = ida_hexrays.decompile(idaapi.get_screen_ea())
        if cur_func is None:
            logging.error(f'aiDAPal: not currently in a function - is ida view synced with hexrays view?')
            return
        sel_code = None
        if self.selection:
            sel_code = get_hexrays_selection()
            if sel_code is None:
                logging.error(f'aiDAPal: no selection')
                return
        logging.info(f'aiDAPal: starting analysis for {cur_func.entry_ea}')
        dref_comments = get_function_data_ref_comments(cur_func.entry_ea)
        if dref_comments == "/*\n*/":
            dref_comments = None
        logging.info(f'aiDAPal: extra juice {dref_comments}')
        logging.debug(f'aiDAPal: model {self.model} selection {self.selection}')
        caller = partial(async_call, cur_func, self.model, extra_context=dref_comments, selected_code=sel_code)
        threading.Thread(target=caller).start()

    # This method is used to update the state of the action (optional)
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class DataAnalysisHandler(ida_kernwin.action_handler_t):
    model = ''
    selection = False

    def __init__(self, model, selection=False):
        self.model = model
        self.selection = selection
        logging.debug(f'aiDAPal: data analysis {model} {selection}')
        ida_kernwin.action_handler_t.__init__(self)

    # This method is called when the menu item is clicked
    def activate(self, ctx):
        # get the current location address and name
        cur_addr = idaapi.get_screen_ea()
        # Is the current address code or data
        if ida_bytes.is_code(ida_bytes.get_full_flags(cur_addr)):
            logging.error(f'aiDAPal: data analysis called on code')
            return
        cur_name = ida_name.get_name(cur_addr)
        logging.info(f'aiDAPal started for {cur_name} at {hex(cur_addr)}')
        data_query = get_data_references_query(cur_addr)
        if data_query == '':
            logging.error(f'aiDAPal: no data references found')
            return
        logging.debug(f'aiDAPal: model {self.model} selection {self.selection}')
        # Pass None for cur_func as we are working with data
        caller = partial(async_call, None, self.model, extra_context=None, selected_code=data_query,
                         data_address=cur_addr)
        threading.Thread(target=caller).start()

    # This method is used to update the state of the action (optional)
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


code_actions = []
data_actions = []
for model in models:
    # Register the full function analysis actions
    action_id = f'{model}_ff'
    code_actions.append(action_id)
    action_desc = ida_kernwin.action_desc_t(
        action_id,  # The unique name of the action
        f'Full Function',  # The label of the menu item
        FunctionDecompilerHandler(model),  # The action handler class
        None,  # Optional shortcut key
        f'Full Function using {model}',  # Tooltip
        199)  # Optional icon ID
    ida_kernwin.register_action(action_desc)

    # Register the selection analysis actions
    action_id = f'{model}_sel'
    code_actions.append(action_id)
    action_desc = ida_kernwin.action_desc_t(
        action_id,  # The unique name of the action
        f'Selection',  # The label of the menu item
        FunctionDecompilerHandler(model, selection=True),  # The action handler class
        None,  # Optional shortcut key
        f'Selection using {model}',  # Tooltip
        199)  # Optional icon ID
    ida_kernwin.register_action(action_desc)

    # Register the data reference analysis actions
    action_id = f'{model}_data'
    data_actions.append(action_id)
    action_desc = ida_kernwin.action_desc_t(
        action_id,  # The unique name of the action
        f'Data',  # The label of the menu item
        DataAnalysisHandler(model, selection=True),  # The action handler class
        None,  # Optional shortcut key
        f'Data using {model}',  # Tooltip
        199)  # Optional icon ID
    ida_kernwin.register_action(action_desc)


class MyHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle):
        # Check if the widget is the disassembly view
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
            for action in code_actions:
                model_name = action.split('_')[0]
                ida_kernwin.attach_action_to_popup(widget, popup_handle, action, f'aiDAPal/{model_name}/')
        # Check if the widget is the disassembly view
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
            for action in data_actions:
                model_name = action.split('_')[0]
                ida_kernwin.attach_action_to_popup(widget, popup_handle, action, f'aiDAPal/{model_name}/')


# Create an instance and install
hooks = MyHooks()
hooks.hook()


def unload_plugin():
    for model in models:
        ida_kernwin.unregister_action(model)
    print("aiDAPal unloaded")
    global hooks
    if hooks is not None:
        hooks.unhook()
        hooks = None


def PLUGIN_ENTRY():
    return aiDAPalPlugin()


# Minimal Plugin Structure Stub
class aiDAPalPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_MULTI | idaapi.PLUGIN_MOD
    comment = "aiDAPal Plugin"
    help = "Analyzes and enhances functions in IDA"
    wanted_name = "aiDAPal"
    wanted_hotkey = 'Ctrl-Shift-D'

    def init(self):
        if not dependencies_loaded:
            ida_kernwin.msg(
                f"IDA {self.wanted_name} plugin ({__file__}) was not loaded due to a missing dependency: {failed_dependency}.\n")
            return ida_idaapi.PLUGIN_SKIP

        ida_kernwin.msg(f"IDA {self.wanted_name} plugin ({__file__}) initialized.\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.msg(f"IDA {self.wanted_name} plugin ({__file__}) running.\n")

    def term(self):
        ida_kernwin.msg(f"IDA {self.wanted_name} plugin ({__file__}) terminated.\n")
