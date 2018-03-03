import manticore

class ManticoreCommand(GenericCommand):
    """Create a manticore context for Symbolic Execution"""
    _cmdline_ = "manticore"
    _syntax_  = "{:s} [-h address func]".format(_cmdline_)
    _aliases_ = ["symexec",]
    _example_ = "{:s} -s main".format(_cmdline_)

    def __init__(self):
        super(ManticoreCommand, self).__init__(complete=gdb.COMPLETE_SYMBOL)
        # self.add_setting("key", "", "RetDec decompilator API key")
        return

    def new_state(self):
        print(" = {}".format(current_arch))
        # Todo; check for arch supported my Manticore
        state = manticore.make_gef()
        self.m = manticore.Manticore(state)
        return

    def add_hook(self, value, func):
        if not self.is_manticore_initiated():
            warn("Using current state as Manticore state")
            self.new_state()

        info("Created hook at {:s}".format(value))
        # Todo; parse hook func.
        def dummy_hook(state):
            pass
        hook_func = dummy_hook

        self.add_hook(value, hook_func)
        return

    def set_symbolic(self, addr, size):
        # Todo;
        return

    def is_manticore_initiated(self):
        if not self.m:
            err("Manticore state is not initiated")
            return False
        return True

    def pre_load(self):
        if PYTHON_MAJOR != 2:
            raise RuntimeError("Manticore requires Python 2, see https://github.com/trailofbits/manticore/issues/45")


    @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        opts = getopt.getopt(argv, "h:")[0]
        if not opts:
            self.usage()
            return

        for opt, arg in opts:
            if opt == "-h":

                # Todo; Split arg
                symbol_or_address = arg
                try:
                    value = gdb.parse_and_eval(symbol_or_address).address
                    value = long(value)
                except gdb.error:
                    # No such symbol, this is an address
                    value = int(symbol_or_address, 16)

                func = None # Todo;
                if not func:
                    warn("Using default. hook func, use the `python` command first first to define it.") # Or use source
                self.add_hook(value, func)
                # elif opt == 
            else:
                self.usage()

        return

register_external_command(ManticoreCommand())
