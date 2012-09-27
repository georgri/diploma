#ifndef DATA_COLLIDER_H_1532_INCLUDED
#define DATA_COLLIDER_H_1532_INCLUDED

/* data_collider.h - functions for data collider capabilities
 */

#include <linux/kernel.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

// Container of module information
struct mod_insn;

// Information about address block
struct addr_info;

// 0) Function to reveal the address and size of the module instruction block
void get_module_address (char* module_name, void ** start_address
	, void ** end_address);

// 1) Function to push instruction accessing memory to the instruction set
int push_new_instruction (struct insn * insn, void *data);

// 2) Function to set breakpoints upon instructions. Number of breakpoints is
// automatically determined. Instructions to set breakpoints are chosen at random.
void set_bp_auto (struct mod_insn * data, int timeout);

// 3) Function to set a single breakpoint upon instruction. This function also
// binds breakpoint handler.
void set_insn_bp (struct insn* insn);

// 4) Function to set "idle" timer to handle situations when breakpoints are not
// triggered for too long.
void set_idle_timer (void);

// 5) Function to reveal the memory address, size and read/write mode
// the instruction is accessing to
void get_mem_attr (struct insn * insn);

// 6) Function to set HW breakpoint upon some address. This function is also
// responsible of binding the handler of triggering the breakpoint.
void set_hw_bp (struct mod_insn * data, struct addr_info * addr_info);

// 7) Function to set a timer to wait for triggering HW bp. This function
// also binds a function to handle the timer alarm event.
void set_hw_timer (void);

// 8) Function to output a warning about triggering an HW bp.
void warning_hw (struct insn* insn1, struct insn* insn2);

// 9) Function to output a warning about memory changing revealed by double reading
void warning_double_read (struct insn * insn);

// 10) Function to unset an HW bp
void unset_hw_bp (struct mod_insn * data, struct insn * insn);

// 11) Function to unset an instruction bp
void unset_insn_bp (struct insn * insn);

// 11.5) Function to disable (not unset) an instruction bp
void disable_insn_bp (struct insn *insn);

// 11.6) Function to enable an (already set but disabled) instruction bp
void enable_insn_bp (struct insn *insn);

// 12) Function to determine a quantity of instuction breakpoints to set.
uint calc_needed_bp (struct mod_insn *data);


//==================== Main functions =================

// 13) Function to initialize data_collider functionality
void data_collider_init (struct mod_insn *data);

int handler_insn_bp_pre_helper(struct kprobe *p, struct pt_regs *regs);

// 14) Function to handle instruction bp triggering event
void handler_insn_bp_pre (struct pt_regs * pt_regs, void * address
					, struct mod_insn * data);

void handler_insn_bp_post_helper(struct kprobe *p, struct pt_regs *regs
								, unsigned long flags);

void handler_insn_bp_post (struct pt_regs * pt_regs, void * address
					, struct mod_insn * data);

int handler_insn_bp_fault_helper(struct kprobe *p, struct pt_regs *regs
								, int trapnr);


// 15) Function to handle HW bp triggering event
void handler_hw_bp_helper(struct perf_event *bp,
						struct perf_sample_data *s_data,
						struct pt_regs *regs);
void handler_hw_bp (struct pt_regs * pt_regs, void * address
					, struct mod_insn * data);

void handler_idle_timeout_helper(unsigned long id);

void handler_idle_timeout(struct mod_insn *data);

void handler_hw_timer_helper(unsigned long id);

// 16) Function to handle timeout hw event (with double read check)
void handler_hw_timeout (struct mod_insn * data);

// 17) Function to unset current breakpoints and setting new
void unset_cur_bp_and_set_new (struct mod_insn * data);

// 18) Function to deinitialize data collider fucntionality
void data_collider_fini (void);
void data_collider_fini_helper (struct mod_insn * data);


#endif // DATA_COLLIDER_H_1532_INCLUDED
