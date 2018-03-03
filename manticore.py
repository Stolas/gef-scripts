import manticore

class ManticoreCommand(GenericCommand):
    """Create a manticore context for Symbolic Execution"""
    _cmdline_ = "manticore"
    _syntax_  = "{:s} [run] [hook <address> <func>] [set_symbolic <data> <label>]".format(_cmdline_)
    _aliases_ = ["symexec",]
    _example_ = "{:s} -s main".format(_cmdline_)

    def __init__(self):
        super(ManticoreCommand, self).__init__(complete=gdb.COMPLETE_SYMBOL)
        # self.add_setting("key", "", "RetDec decompilator API key")
        return

    def new_state(self, use_current_state=True):
        # Todo; check for arch supported my Manticore
        print(" = {}".format(current_arch.__class__))

        # For now, use out of the box manticore instead of creating our own state.
        state = manticore.manticore.make_linux(get_filepath())
        if use_current_state:
            # Todo; Set memory to current state
            # state._platform.current.memory
            pass

        self.m = manticore.Manticore(state)
        return

    def add_hook(self, value, func):
        if not self.is_manticore_initiated():
            warn("Using current state as Manticore state")
            self.new_state()

        info("Created hook at {:s}".format(hex(value)))
        # Todo; parse hook func.
        def dummy_hook(state):
            pass
        hook_func = dummy_hook

        self.m.add_hook(value, hook_func)
        return

    def set_symbolic(self, data, label='INPUT', wildcard='+', string=False, taint=frozenset()):
        self.m.initial_state.symbolicate_buffer(data, label='INPUT', wildcard='+', string=False, taint=frozenset())
        return

    def is_manticore_initiated(self):
        try:
            self.m = self.m
        except AttributeError:
            err("Manticore state is not initiated")
            return False
        return True

    def pre_load(self):
        if PYTHON_MAJOR != 2:
            raise RuntimeError("Manticore requires Python 2, see https://github.com/trailofbits/manticore/issues/45")

    # @only_if_gdb_running       # not required, ensures that the debug session is started
    @only_if_gdb_target_local  # Required as Manticore requires the binary as I do not have patched Manticore
    def do_invoke(self, argv):
        try:
            opt = argv[0]
            args = argv[1:]
        except IndexError:
            self.usage()
            return

        if opt == "run":
            if self.is_manticore_initiated():
                self.m.run()
            return
        elif opt == "hook":
            symbol_or_address = args[0]
            try:
                value = gdb.parse_and_eval(symbol_or_address).address
                value = long(value)
            except:
                # No such symbol, this is an address
                value = long(int(symbol_or_address, 16))

            try:
                func = args[1]
                # Todo; Resolve str to pointer
            except IndexError:
                warn("Using default. hook func, use the `python` command first first to define it.") # Or use source
                func = None

            self.add_hook(value, func)
            return
        elif opt == "set_symbolic":
            try:
                data = args[0]
                label = args[1]
                self.set_symbolic(data, label)
                return
            except IndexError:
                pass
        else:
            pass

        self.usage()
        return

register_external_command(ManticoreCommand())
