/* ir.h - definition of the intermediate representation (IR) of the code. */

#ifndef IR_H_1801_INCLUDED
#define IR_H_1801_INCLUDED

#include <linux/kernel.h>
#include <linux/list.h>
#include <kedr/asm/insn.h> /* instruction analysis facilities */

/* A node of the IR (i.e. in the instruction list)  */
struct kedr_ir_node;
struct kedr_ir_node
{
	/* The ordered list of the instructions. */
	struct list_head list; 
	
	/* A buffer containing the instruction. */
	u8 insn_buffer[X86_MAX_INSN_SIZE];
	
	/* The instruction decoded from insn_buffer */
	struct insn insn;
	
	/* Address of the instruction in the original function, 0 if the 
	 * instruction was added only during the instrumentation. */
	unsigned long orig_addr;
	
	/* Offset of the instruction in the instrumented instance of the 
	 * function from the beginning of that instance. */
	long offset;
	
	/* If the node represents a direct relative jump within the
	 * current function, 'dest_inner' points to the node corresponding
	 * to the destination of the jump. This field is NULL if the node
	 * represents something else (this can also be used when choosing 
	 * whether to use a short or a near jump). */
	struct kedr_ir_node *dest_inner;
	
	/* Nonzero if the node represents a jump which destination is not 
	 * 'dest_inner->first' as for many other nodes but rather 
	 * 'dest_inner->last->(next)'. A jump past the end of the block is
	 * one of the examples. Default value: 0. */
	int jump_past_last;
	
	/* (see insn_jumps_to()) */
	unsigned long dest_addr;
	
	/* If the node represents a call/jmp rel32 that refers to something
	 * outside of the original function or represents an instruction 
	 * with RIP-relative addressing mode, 'iprel_addr' is the address it 
	 * refers to. The address should be the same in the instrumented 
	 * code but the offset will change. 
	 * 
	 * This field remains 0 if the node represents something else. 
	 * 
	 * [NB] Although 'dest_addr' is available, 'iprel_addr' is necessary
	 * too. For example, the former is 0 for the instructions with 
	 * IP-relative addressing and is generally used to process control 
	 * transfer instructions when spliting the code into blocks. 
	 * The latter is mainly used to prepare relocation of the 
	 * instrumented code. Among other things, 'iprel_addr' is 0 for the
	 * control transfer instructions without IP-relative addressing 
	 * (e.g. 'ret', 'int'). */
	unsigned long iprel_addr; 
	
	/* During the instrumentation, the instruction may be replaced with
	 * a sequence of instructions. 'first' points to the first node
	 * of that sequence, 'last' - to the last one. If no 
	 * instructions have been  added, both 'first' and 'last'
	 * point to this very node. */
	struct kedr_ir_node *first;
	struct kedr_ir_node *last;
	
	/* This field allows to place the node into a hash table when it is
	 * needed. */
	struct hlist_node hlist;
	
	/* Nonzero if this IR node corresponds to a start of a code block
	 * in the original code, 0 otherwise. Default value: 0. */
	int block_starts;
	
	/* Register usage mask for the instruction. To simplify debugging,
	 * its default value should be as if the instruction used all the 
	 * general-purpose registers. */
	unsigned int reg_mask;
	
	/* Nonzero if the node corresponds to an inner jmp near indirect
	 * that uses a jump table. Default value: 0. */
	int inner_jmp_indirect;
	
	/* Nonzero if a relocation of type KEDR_RELOC_ADDR32 should be 
	 * performed for the instruction. This is used in handling of the
	 * forward jumps out of the blocks. Default value: 0. */
	int needs_addr32_reloc;
	
	// TODO: add more fields if necessary
};

/* Construct an IR node with all fields initialized to their default values.
 * The function returns the pointer to the constructed and initialized node
 * on success, NULL if there is not enough memory to complete the operation.
 */
struct kedr_ir_node *
kedr_ir_node_create(void);

/* Destroy the node and release memory it occupies. 
 * If 'node' is NULL, the function does nothing. */
void
kedr_ir_node_destroy(struct kedr_ir_node *node);


#endif // IR_H_1801_INCLUDED
