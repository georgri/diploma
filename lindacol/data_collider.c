/* data_collider.c - functions for data collider capabilities
 */

#include <linux/slab.h>
#include <kedr/asm/insn.h>
#include <linux/timer.h>
#include <linux/sched.h>
#include <asm-generic/ptrace.h>
#include <linux/capability.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/random.h>

#include "data_collider.h"
#include "debug_util.h"
#include "util.h"

// TODO: Function to initialize mod_insn structure. Initial size must be 0!
#define MAX_INSNS_SIZE 4096
// Container of module information
struct mod_insn {
	char * module_name;
	void * address; // of the beginning in memory
	int instructions_total; // the number of all instructions in module (for stats)
	struct insn ** insns; // set of pointers to instructions accessing memory
	int size; // size of insns
	int bp_count; // number of bp set
	struct insn * insn; // null if we are not doing some analysis at the moment
	struct perf_event * __percpu *hw_bp; // there may be only one HW bp
};


unsigned int shift1[4] = {6, 2, 13, 3};
unsigned int shift2[4] = {13, 27, 21, 12};
unsigned int shift3[4] = {18, 2, 7, 13};
unsigned int offset[4] = {4294967294, 4294967288, 4294967280, 4294967168};

unsigned int randStates[32];



// A and C are constants  
unsigned LCGStep(unsigned *z, unsigned A, unsigned C)  
{  
  return *z = (A * (*z) + C);  
}

unsigned int TausStep(unsigned int *z, int S1, int S2, int S3, unsigned int M)
{
	unsigned int b;
//	debug_util_print_string("\nThe debug info from 'rand()' function:\n");
//	debug_util_print_string("*z = ");
//	debug_util_print_u64(*z, "%x");
//	debug_util_print_string("; S1 = ");
//	debug_util_print_u64(S1, "%x");
//	debug_util_print_string("; S2 = ");
//	debug_util_print_u64(S2, "%x");
//	debug_util_print_string("; S3 = ");
//	debug_util_print_u64(S3, "%x");
//	debug_util_print_string("; M = ");
//	debug_util_print_u64(M, "%x");	
//	debug_util_print_string("; *z << S1 = ");
//	debug_util_print_u64(*z << S1, "%x");
//	debug_util_print_string("; (*z << S1) ^ *z = ");
//	debug_util_print_u64( (*z << S1) ^ *z, "%x");
//	debug_util_print_string("; ((*z << S1) ^ *z) >> S2 = ");
//	debug_util_print_u64( ((*z << S1) ^ *z) >> S2, "%x");
//	debug_util_print_string("\n");
    b = (((*z << S1) ^ *z) >> S2);
//    debug_util_print_string("b = ");
//    debug_util_print_u64(b, "%x");
//    debug_util_print_string("; (*z) & M = ");
//    debug_util_print_u64(*z & M, "%x");
//    debug_util_print_string("; (*z) & M = ");
//    debug_util_print_u64(*z & M, "%x");
//    debug_util_print_string("; (*z) & M = ");
//    debug_util_print_u64(*z & M, "%x");
//    debug_util_print_string("; ((*z) & M) << S3 = ");
//    debug_util_print_u64((*z & M) << S3, "%x");
//    debug_util_print_string("; (((*z) & M) << S3) ^ b = ");
//    debug_util_print_u64(((*z & M) << S3) ^ b, "%x");
    (*z) = ((((*z) & M) << S3) ^ b);
    return *z;
}


unsigned int randInt(void)
{
//    debug_util_print_string("\nThe integers to generate a 'random' number: ");
//    debug_util_print_u64(randStates[0], "%d");
//    debug_util_print_string(" ");
//    debug_util_print_u64(randStates[1], "%d");
//    debug_util_print_string(" ");
//    debug_util_print_u64(randStates[2], "%d");
//    debug_util_print_string(" ");
//    debug_util_print_u64(randStates[3], "%d");
    return ( TausStep(randStates, 13, 19, 12, 4294967294UL) ^  // p1=2^31-1  
	    TausStep(randStates + 1, 2, 25, 4, 4294967288UL) ^    // p2=2^30-1  
	    TausStep(randStates + 2, 3, 11, 17, 4294967280UL) ^   // p3=2^28-1  
	    LCGStep(randStates + 3, 1664525, 1013904223UL));
}

static int rand(void) {
	// The idea of such a generator is from
	// http://http.developer.nvidia.com/GPUGems3/gpugems3_ch37.html
	return randInt();
}

static void rand_init(void) {
	// Setting a seed for rand() function
	get_random_bytes(randStates, sizeof(int) * 4);
}



//// Information about address block
//struct addr_info {
//	void * address;
//	uint size;
//	const char content[sizeof(int)];
//	uint mode; // HW_BREAKPOINT_W - write mask, HW_BREAKPOINT_R - read mask
//};


struct mod_insn data;

struct timer_list idle_timer;
struct timer_list hw_timer;
DECLARE_WAIT_QUEUE_HEAD(wq);


// I need to implement a function which prints convenient info about an instruction.
// It takes an address, decodes it, prints some info and returns nothing.
void pr_info_addr(void * kaddr) {
	struct insn insn;
	kernel_insn_init(&insn, kaddr);
	// debug_util_print_string(str);
	// debug_util_print_u64( data, "%d"); - like this
//	debug_util_print_string("\nThe number of legacy prefixes is ");
//	debug_util_print_u64(X86_NUM_LEGACY_PREFIXES, "%d");
	insn_get_prefixes(&insn);
	debug_util_print_string("\nThe instruction at address ");
	debug_util_print_u64(PTR_ERR(kaddr), "%p");
	debug_util_print_string(" has following legacy prefixes: ");
	debug_util_print_hex_bytes(insn.prefixes.bytes, X86_NUM_LEGACY_PREFIXES);
	debug_util_print_string("\nRex prefix: ");
	debug_util_print_u64(insn.rex_prefix.value, "%1x");
	debug_util_print_string("\nVex_prefix: ");
	debug_util_print_u64(insn.vex_prefix.value, "%1x");
	
	insn_get_opcode(&insn);
	debug_util_print_string("\nOpcode: ");
	debug_util_print_hex_bytes(insn.opcode.bytes, 3);
	
	insn_get_modrm(&insn);
	debug_util_print_string("\nModR/M: ");
	debug_util_print_u64(insn.modrm.value, "%1x");
	
	insn_get_sib(&insn);
	debug_util_print_string("\nSib: ");
	debug_util_print_u64(insn.sib.value, "%1x");
	
	insn_get_displacement(&insn);
	debug_util_print_string("\nDisplacement: ");
	debug_util_print_u64(insn.displacement.value, "%1x");
	
	insn_get_immediate(&insn);
	debug_util_print_string("\nImmediate data: ");
	debug_util_print_u64(insn.immediate.value, "%1x");
	
	insn_get_length(&insn);
	debug_util_print_string("\nThe length of instruction is ");
	debug_util_print_u64((int)insn.length, "%d");
	
	debug_util_print_string("\nThe whole instruction looks like this: ");
	debug_util_print_hex_bytes(kaddr, insn.length);
	
	debug_util_print_string("\nThe address to the next instruction is ");
	debug_util_print_u64(PTR_ERR(insn.next_byte), "%p");

	// Attributes are already gotten due to getting of modrm byte.	
	debug_util_print_string("\nAddressing method and operand types: ");
	debug_util_print_u64(insn.attr.addr_method1 + 'A', "%c");
	debug_util_print_u64(insn.attr.opnd_type1 + 'a', "%c");
	debug_util_print_u64(insn.attr.addr_method2 + 'A', "%c");
	debug_util_print_u64(insn.attr.opnd_type2 + 'a', "%c");
	
	debug_util_print_string("\nNumber of operand bytes (whatever it means): ");
	debug_util_print_u64(insn.opnd_bytes, "%d");
	debug_util_print_string("\nNumber of address bytes (whatever it means): ");
	debug_util_print_u64(insn.addr_bytes, "%d");

	if (insn_is_mem_read(&insn)) {
		debug_util_print_string("\nThe instruction is reading from memory.");
	}
	if (insn_is_mem_write(&insn)) {
		debug_util_print_string("\nThe instruction is writing to memory.");
	}
	if (!insn_is_mem_read(&insn) && !insn_is_mem_write(&insn)) {
		debug_util_print_string("\nThe instruction is not reading nor writing from/to memory.");
	}

	debug_util_print_string("\nThis instruction was decoded under the ");
	debug_util_print_u64(insn.x86_64 ? 64 : 32, "%d");
	debug_util_print_string("-bit architecture\n");
	
	//	/* Legacy prefixes
	//	 * prefixes.bytes[X86_NUM_LEGACY_PREFIXES - 1]: last prefix */
	//	struct insn_field prefixes;	
	//	
	//	struct insn_field rex_prefix;	/* REX prefix */
	//	struct insn_field vex_prefix;	/* VEX prefix */
	//	struct insn_field opcode;	/*
	//					 * opcode.bytes[0]: opcode1
	//					 * opcode.bytes[1]: opcode2
	//					 * opcode.bytes[2]: opcode3
	//					 */
	//	struct insn_field modrm;
	//	struct insn_field sib;
	//	struct insn_field displacement;
	//	union {
	//		struct insn_field immediate;
	//		struct insn_field moffset1;	/* for 64bit MOV */
	//		struct insn_field immediate1;	/* for 64bit imm or off16/32 */
	//	};	
	//	insn_attr_t attr;
	//	unsigned char opnd_bytes;
	//	unsigned char addr_bytes;
	//	unsigned char length;
	//	unsigned char x86_64;
	//
	//	const insn_byte_t *kaddr;	/* kernel address of insn to analyze */
	//	const insn_byte_t *next_byte;


	///* Instruction attributes */
	//typedef struct insn_attr
	//{ 
	//	/* Attributes of the instruction as a whole */
	//	unsigned int attributes; 
	//	
	//	/* Codes for the addressing method and the operand type for two
	//	 * operands */
	//	unsigned char addr_method1;
	//	unsigned char opnd_type1;
	//	unsigned char addr_method2;
	//	unsigned char opnd_type2;
	//} insn_attr_t;
}


// 0) Function to reveal the address and size of the module instruction block
void get_module_address (char* module_name, void ** start_address
						, void ** end_address) {
	// Функция узнаёт адрес начала и конца блока инструкций.
	//	Как найти модуль:
	//	http://stackoverflow.com/questions/3289617/how-to-use-find-module
	//	struct module *mod;
	//	mutex_lock(&module_mutex);
	//	mod = find_module("MODULE_NAME");
	//	if(!mod) {
	//	    printk("Could not find module\n");
	//	    return;
	//	}
	//	mutex_unlock(&module_mutex);
	
	struct module *mod;

    if (!capable(CAP_SYS_MODULE)) {
       	pr_info("lindacol: unable to get module address - system not capable?");
        return;
    }

    if (mutex_lock_interruptible(&module_mutex) != 0) {
    	pr_info("lindacol: unable to get module address - fail to get mutex_lock.");
    	return;
    }

    mod = find_module(module_name);
    if (!mod) {
		pr_info("lindacol: unable to get module address - fail of 'find_module()'");
		goto out;
    }

	out:
    mutex_unlock(&module_mutex);
	if (mod == NULL) {
		pr_info("lindacol: unable to find module %s for some reason.", module_name);
		return;
	}
	

	//	- как найти адрес блоков инструкций в модуле?
	/*
	Оказалось, элементарно. Вот обнаружить это было неэлементарно. Такие вещи не
	гуглятся. По крайней мере, у меня.
	Кусок кода из 'struct module':
	//If this is non-NULL, vfree after init() returns
	void *module_init;
	//Here is the actual code + data, vfree'd on unload.
	void *module_core;
	// The size of the executable code in each section.
	unsigned int init_text_size, core_text_size;
	
	Мы намерены запускать наш модуль _после_ того, как тестируемый модуль загружен.
	Поэтому, по семантике мы должны исследовать только секцию "core_text", 
	но не "init_text".
	*/
	(*start_address) = mod->module_core; // seems legit
	(*end_address) = mod->module_core + mod->core_text_size;
	// Ну клёво, попробую запустить.
	
	// Чтобы проверить, что это всё работает, а не просто так =)
	debug_util_print_string("\nGetting of module init and end addresses: ");
	debug_util_print_string(module_name);
	debug_util_print_string("\nStart address: ");
	debug_util_print_u64(PTR_ERR(*start_address), "%p");
	debug_util_print_string("; End address: ");
	debug_util_print_u64(PTR_ERR(*end_address), "%p");
	debug_util_print_string("; Size of instruction section: ");
	debug_util_print_u64(mod->core_text_size, "%d");
	debug_util_print_string("\n");
	
	// Вроде, работает! Клёво, молодец!
}



// 1) Function to push instruction accessing memory to the instruction set
int push_new_instruction (struct insn * insn, void *data) {
	// Функция пихает инструкцию обращения к памяти в массивчик
	/*
		- вызываем 'is_insn_read'/'is_insn_write', при положительном результате:
		- копируем содержимое insn в data->insns[size] (с помощью memcpy или вручную)
		- data->size++;
	*/	
	struct mod_insn *data_casted;
	struct insn* temp_insn;
//	debug_util_print_string("\nInstruction under processing: ");
//	debug_util_print_u64(PTR_ERR(insn->kaddr), "%p");
	data_casted = (struct mod_insn*) data;
	data_casted->instructions_total ++;
//	debug_util_print_string("\nThe current size of instructions in array: ");
//	debug_util_print_u64(data_casted->size, "%d");
	if (data_casted->size < MAX_INSNS_SIZE) {
		if (insn_is_mem_read(insn) || insn_is_mem_write(insn)) {
			// Надо выделять память под каждую инструкцию, присваивать указатель, а потом 
			// по нему копировать. Иначе будет сложно делать навигацию по такому массивчику.
			temp_insn = NULL;
			temp_insn = (struct insn*)kzalloc(sizeof(struct insn), GFP_KERNEL);
			if (temp_insn == NULL) {
				debug_util_print_string("\nThere is a failure in memory allocation: the ");
				debug_util_print_u64(data_casted->size, "%d");
				debug_util_print_string(" instructions allocated\n");
				BUG_ON(temp_insn == NULL);
			}
			memcpy((void*) temp_insn, (void*) insn, sizeof(struct insn));
			data_casted->insns[data_casted->size] = temp_insn;
			data_casted->size++;
		} else {
//			debug_util_print_string("\nThe instruction is not reading nor writing... ");
//			debug_util_print_u64(PTR_ERR(insn->kaddr), "%p");
		}
	}
	// returns 0 if OK, some negative integer to stop
	return (data_casted->size <= MAX_INSNS_SIZE) ? 0 : -1;
	
	// TESTED! =)
}

int determine_bp_quantity(struct mod_insn *data, int timeout) {
	// Если по таймауту, то +1% от количества всех инструкций
	// В противном случае нужно добрать до 10% от количества всех инструкций	
	if (timeout) {
		return min(data->size / 100, data->size - data->bp_count);
	} else {
		return max(0, data->size / 10 - data->bp_count);
	}
}

// 2) Function to set breakpoints upon instructions. Number of breakpoints is
// automatically determined. Instructions to set breakpoints are chosen at random.
void set_bp_auto (struct mod_insn * data, int timeout) {
	// Функция автоматически определяет число точек прерывания, которые надо поставить.
	// Ставит это количество точек прерывания.
	// Вообще, эта функция должна бы выполняться не в параллели с чем-либо ещё.
	// TODO: В функции insn_init обнулять значение доп. полей
	int bp_to_set, index;
	bp_to_set = determine_bp_quantity(data, timeout);
	debug_util_print_string("\nThe determined number of instructions to set bp upon is:");
	debug_util_print_u64(bp_to_set, "%d");
	while (bp_to_set > 0) { // Эта функция может и зациклиться, при удачном стечении обстоятельств.
		index = ((rand() % data->size) + data->size) % data->size;
		if (!data->insns[index]->is_bp || data->insns[index]->is_disabled) {
			//debug_util_print_string("\nSeting a BP upon instruction with index: ");
			//debug_util_print_u64(index, "%d");
			// Мы нашли инструкцию, на которую не поставлена точка прерывания.
			set_insn_bp(data->insns[index]); // Поставит bp или активирует неактивную
			// Если вдруг даже не удалось поставить точку прерывания, всё равно уменьшаем
			// счётчик. Значит, произошло что-то нехорошее, и сейчас не надо пытаться 
			// поставить много точек. В следующий раз может повезти больше.
			bp_to_set --;
		}
	}
	debug_util_print_string("\n");
	return;
	
	// TESTED!
}

// 3) Function to set a single breakpoint upon instruction. This function also
// binds breakpoint handlers.
void set_insn_bp (struct insn* insn) {
	//http://lxr.free-electrons.com/source/samples/kprobes/kprobe_example.c
	int ret;
	if (insn->is_bp) {
		// Может быть задизейблена, так что надо ещё проверить
		if (!insn->is_disabled) {
		// Вызывающая функция, вообще говоря, должна позаботиться, чтобы такого
		// не случилось
			debug_util_print_string("\nIt seems that instruction bp is already set and enabled: ");
			debug_util_print_u64(PTR_ERR(insn->kaddr), "%p");
			return;
		} else {
			enable_insn_bp(insn); // передаём ответственность фунции активации
			return;
		}
	}
	// жалко, что в Си нет оператора clear(...), который бы очищал всю структуру...
	insn->kp.addr = (void*)insn->kaddr;
	insn->kp.pre_handler = handler_insn_bp_pre_helper;
	insn->kp.post_handler = handler_insn_bp_post_helper;
	insn->kp.fault_handler = handler_insn_bp_fault_helper;
	
	//ret = 0; // Эмулирует успешный вызов, если надо
	ret = (register_kprobe(&insn->kp));
	if (ret < 0) {
		debug_util_print_string("\nRegister_kprobe failed, returned: ");
		debug_util_print_u64(ret, "%d");
		return;
	}
	
	insn->is_bp = 1; // Ставим признак того, что точка прерывания поставлена.
	insn->is_disabled = 0; // Обязательно сбрасываем этот флаг при установке ТП
	data.bp_count ++;
		
	debug_util_print_string("\nPlanted kprobe at: ");
	debug_util_print_u64(PTR_ERR(insn->kp.addr), "%p");
	debug_util_print_string(", ret code = ");
	debug_util_print_u64(ret, "%d");
	return;
}


// 4) Function to set "idle" timer to handle situations when breakpoints are not
// triggered for too long.
void set_idle_timer (void) {
	// Функция ставит таймер несрабатываемости (ставим таймер на какое-то
	// фиксированное количество времени, потому что срабатывание этого таймера,
	// вообще, крайне маловероятно).
	// Как поставить таймер, как обрабатывать события таймера
	// http://www.ibm.com/developerworks/linux/library/l-timers-list/?ca=drs-	
	// Нам нужен хэндлер, который бы принимал пареметр таймера - unsigned long.
	// Пусть это будет 100 милисекунд.
	if (timer_pending(&idle_timer)) {
		del_timer(&idle_timer);	
	}
	setup_timer(&idle_timer, &handler_idle_timeout_helper, 0);
	if( mod_timer(&idle_timer, jiffies + msecs_to_jiffies(100)) ) {
		pr_err("lindacol: For whatever reason I'm unable to set the idle timer!");
	}
}

// 5) Function to reveal the memory address, size and read/write mode
// the instruction is accessing to
void get_mem_attr (struct insn * insn) {
	// Функция распознавания адреса памяти
	/*
		Вот 85% инструкций, которые достаточно расшифровать:
		- Инструкции с Mod R/M байтом, использующие для адресации 
		  только регистры общего назначения (addressing methods: 
		  E, M; см. Intel's Manual Vol2B, раздел A.2.1).
		- Инструкции с addressing method O (direct offset MOV).
		- Строковые операции (addressing methods: X, Y)
		- XLAT
	*/
	/*
		Вот что в instruction manual:
		E: A Mod R/M byte follows the opcode and specifies the operand. The operand
		is either a general-purpose register or a memory address. If it is a memory
		address, the address is computed rom a segment register and any of the
		following values: a base register, and index register, a scaling factor,
		a displacement.
		
		M: The ModR/M byte may refer only to memory (for example, MOUND, LES,
		LDS, LSS, LFS, LGS, CMPXCHG8B)

		O: The instruction has no ModR/M byte. The offset of the operand is coded 
		as a word or double word (depending on address size attribute) in the
		instruction. No base register, index register, or scaling factor can 
		be applied (for example, MOV (A0-A3)).

		X: Memory addressed by the DS:rSI register pair (for example, MOVS, CMPS,
		OUTS, or LODS).
		
		Y: Memory addressed by the ES:rDI register pair (for example, MOVS, CMPS,
		INS, STOS, or SCAS).
	*/
		
}

// 6) Function to set HW breakpoint upon some address. This function is also
// responsible of binding the handler of triggering the breakpoint.
void set_hw_bp (struct mod_insn * data, struct addr_info * addr_info) {
	// Функция расстановки HWbp + привязка хэндлера
	// см. заголовочный файл hw_breakpoint.h
	/*
		http://lxr.free-electrons.com/source/include/linux/hw_breakpoint.h#L36
		http://lwn.net/Articles/353050/
		register_wide_hw_breakpoint
	*/
	int ret;
	struct perf_event_attr attr;

	if (data->insn->is_hw) {
		pr_info("lindacol: Trying to set HW bp while it's already set: 0x%p",
			addr_info->address);
		return;
	}

	hw_breakpoint_init(&attr);
	attr.bp_addr = (unsigned long)addr_info->address;
	switch (addr_info->size) {
		case 1: attr.bp_len = HW_BREAKPOINT_LEN_1; break;
		case 2: attr.bp_len = HW_BREAKPOINT_LEN_2; break;
		case 4: attr.bp_len = HW_BREAKPOINT_LEN_4; break;
		case 8: attr.bp_len = HW_BREAKPOINT_LEN_8; break;
		default: attr.bp_len = HW_BREAKPOINT_LEN_4; 
				addr_info->size = 4; break; // Мало ли что может случиться
	}
	
	if (addr_info->mode) {
		attr.bp_type = addr_info->mode;
	} else {
		attr.bp_type = HW_BREAKPOINT_W | HW_BREAKPOINT_R; // Опять же, мало ли...
	}

	data->hw_bp = register_wide_hw_breakpoint(&attr, handler_hw_bp_helper, NULL);
	data->insn->is_hw = 1;
	if (IS_ERR((void __force *) data->hw_bp)) {
		ret = PTR_ERR((void __force *)data->hw_bp);
		pr_info("lindacol: Something has gone wrong while setting HW bp: 0x%p", 
			addr_info->address);
		unset_hw_bp(data, data->insn);
	}
}

// 7) Function to set a timer to wait for triggering HW bp. This function
// also binds a function to handle the timer alarm event.
void set_hw_timer (void) {
	// Функция установки таймера бездействия hw bp.
	// Ну, скорее всего, эта функция даже не понадобится, потому что я
	// буду вместо неё буду использовать таймер в пре хендлере прерывания
	// инструкции.
	if (timer_pending(&hw_timer)) { // Такого быть, вообще говоря, не должно.
		// То есть, мы хотим установить таймер на срабатывание hw bp, когда мы ждём
		// срабатывания другой hw bp. Как-то странно.
		pr_err("lindacol: Trying to set another HW bp timer... Strange!");
		return;
	}
	setup_timer(&hw_timer, &handler_hw_timer_helper, (unsigned long)(data.insn));
	if( mod_timer(&hw_timer, jiffies + msecs_to_jiffies(5)) ) {
		pr_err("lindacol: For whatever reason I'm unable to set the HW timer!");
	}
}

// 8) Function to output a warning about triggering an HW bp.
void warning_hw (struct insn* insn1, struct insn* insn2) {
	// Функция плюёт предупреждение о стабатывании HW: формат:
	/*
		Warning: HardWare breakpoint triggered!
		адрес памяти
		содержимое памяти 1, содержимое памяти 2
		размер памяти 1, размер памяти 2
		mode r/w 1, mode r/w 2
		инструкция 1, инструкция 2
		содержимое регистров 1, содержимое регистров 2
	*/
}

// 9) Function to output a warning about memory changing revealed by double reading
void warning_double_read (struct insn * insn) {
	// Функция плюёт предупреждение об изменении памяти.
	/*
		Warning: Memory change detected on double read!
		module name:
		memory address
		memory content before, after
		memory size1, memory size2
		memory access mode1, memory access mode2
		instruction:
		pt_regs:
	*/
	
}

// 10) Function to unset an HW bp
void unset_hw_bp (struct mod_insn * data, struct insn * insn) {
	// Функция снимает HW bp
	// Тут надо рассмотреть возможность расширения структуры insn 
	// данными о HW bp - DONE
	if (data->hw_bp == NULL || data->insn->is_hw == 0) {
		pr_info("lindacol: Trying to unset HW bp which is not set:");
	}
	if (data->insn == NULL || data->insn->is_bp == 0) {
		pr_info("lindacol: Trying to unset HW bp while insn bp is not set.");
	}
	unregister_wide_hw_breakpoint(data->hw_bp);
	data->hw_bp = NULL;
	data->insn->is_hw = 0;
	if (data->insn->insn_hw) {
		data->insn->insn_hw->is_hw = 0;
		data->insn->insn_hw = NULL;
	}
	pr_info("lindacol: HW bp unset: 0x%p", data->insn->addr_info.address);
}

// 11) Function to unset an instruction bp
void unset_insn_bp (struct insn * insn) {
	// Функция пытается снять как enabled, так и disabled точки прерывания.
	// Если вызвать из какого-либо хендлера, то будет дедлок, вместо этой фунции
	// надо использовать disable_insn_bp()
	// Функция снимает insn bp (в insn должна быть структура kprobes)
	if (insn == NULL) return; // Очень важно!
	if (!insn->is_bp) {
		debug_util_print_string("\nTrying to unset not set bp: ");
		debug_util_print_u64(PTR_ERR(insn->kaddr), "%p");
		return;
	}
	
	unregister_kprobe(&(insn->kp)); // returns nothing
	if (!insn->is_disabled) {
		// Точка прерывания была активна -> уменьшаем счётчик
		data.bp_count --;
	}
	insn->is_bp = 0;
	insn->is_disabled = 0; // на всякий случай, мало ли чего
	insn->pt_regs = NULL;
	
	debug_util_print_string("\nInstruction bp is unset: ");
	debug_util_print_u64(PTR_ERR(insn->kaddr), "%p");
}

// 11.5) Function to disabpe the bp (not unset)
void disable_insn_bp (struct insn * insn) {
	// Функция не снимает bp, а только деактивирует её. Это помогает избежать дедлоков
	// в хендлерах kprobes.
	int ret = 0;
	if (insn == NULL) return;
	if (!insn->is_bp) {
		debug_util_print_string("\nTrying to disable not set bp: ");
		debug_util_print_u64(PTR_ERR(insn->kaddr), "%p");
		return;
	}
	if (insn->is_disabled) {
		debug_util_print_string("\nTrying to disable already disabled bp: ");
		debug_util_print_u64(PTR_ERR(insn->kaddr), "%p");
		return;
	}
	ret = disable_kprobe(&(insn->kp));
	if (ret < 0) {
		debug_util_print_string("\nFailed to disable a bp: ");
		debug_util_print_u64(PTR_ERR(insn->kaddr), "%p");
		return;
	}
	insn->is_disabled = 1;
	data.bp_count --;
	debug_util_print_string("\nInstruction bp is disabled: ");
	debug_util_print_u64(PTR_ERR(insn->kaddr), "%p");
}

// 11.6) Function to enable the bp (already set)
void enable_insn_bp (struct insn * insn) {
	// Функция активирует точку прервания, которая уже установлена, но была деактивирована
	int ret = 0;
	if (insn == NULL) return;
	if (!insn->is_bp) {
		debug_util_print_string("\nTrying to enable not set bp: ");
		debug_util_print_u64(PTR_ERR(insn->kaddr), "%p");
		return;
	}
	if (!insn->is_disabled) {
		debug_util_print_string("\nTrying to enabled not disabled bp: ");
		debug_util_print_u64(PTR_ERR(insn->kaddr), "%p");
		return;
	}
	ret = enable_kprobe(&(insn->kp));
	if (ret < 0) {
		debug_util_print_string("\nFailed to enable a bp: ");
		debug_util_print_u64(PTR_ERR(insn->kaddr), "%p");
		return;
	}	
	insn->is_disabled = 0;
	data.bp_count ++; // число установленных точек прерывания
	debug_util_print_string("\nInstruction bp is enabled: ");
	debug_util_print_u64(PTR_ERR(insn->kaddr), "%p");	
}



//==================== Main functions =================

// 13) Function to initialize main data_collider functionality
/*
	- узнать адрес начала и размер тестируемого модуля
	- запуск декодера - for each insn - запустить функцию, которая пихает
		инструкцию обращения к памяти в массивчик (mod_insn)
	- вызов функции, которая ставит ТП на начальный набор инструкций
	- ставит таймер на бездействие системы
*/

void data_collider_init (struct mod_insn *data) {
	void * start_kaddr = NULL, * end_kaddr = NULL;
	int i, j;

	// Generate an initial seed for rand() function.
	rand_init();
	
	// TODO: передавать имя модуля в параметре
	get_module_address ("snd", &start_kaddr, &end_kaddr);
	// На этом этапе было бы неплохо вывести эти адреса в дебаг ФС - сделано.
	
	data->insns = NULL;
	data->insns = (struct insn**)kzalloc(4096 * sizeof(struct insn *)
			, GFP_KERNEL);
	if (data->insns == NULL) {
		debug_util_print_string("\nUnable to allocate a memory for insn pointers!");
		BUG_ON(data->insns == NULL);
	}
	
	data->size = 0; // But it must be in an initialization function of mod_insn!!! // later, bro...
	data->bp_count = 0; // same sh-t
	data->instructions_total = 0;
	data->insn = NULL;
	kedr_for_each_insn((unsigned long) start_kaddr, (unsigned long) end_kaddr,
		& push_new_instruction, (void *) data);
	
	// Было интересно для статистики
	debug_util_print_string("\nThe total number of all instructions: ");
	debug_util_print_u64(data->instructions_total, "%d");
	
	// Интересны результаты такого действа - хватит ли памяти, сколько удастся выдернуть
	// инструкций из "real-life" модуля.
	debug_util_print_string("\nThe number of read/write instruction structs were allocated: ");
	debug_util_print_u64(data->size, "%d");
	debug_util_print_string(" (");
	debug_util_print_u64((data->size) * 100 / (data->instructions_total), "%d");
	debug_util_print_string(".");
	debug_util_print_u64(((data->size) * 1000 / (data->instructions_total)) % 10, "%d");
	debug_util_print_string("% of total)");
	
	debug_util_print_string("\nThe first 10 pointers to these instructions \n");
	j = (data->size > 10) ? 10 : data->size;
	for (i = 0; i < j; i++) {
		debug_util_print_u64(PTR_ERR(data->insns[i]->kaddr), "%p");
		debug_util_print_string(" ");
	}
	
	debug_util_print_string("\n");
	
	set_bp_auto (data, 0);
	//set_idle_timer();
	// TODO: По-моему, до сих пор не написан обработчик несрабатывания
	// точек прерывания.
	return;
}

// 13.5 - Обработчик срабатывания таймера
void handler_idle_timeout_helper(unsigned long id) {
	// Вне зависимости от контекста (id), мы тут можем сделать только одно.
	handler_idle_timeout(&data);
}

// Обработчик слишком долгого несрабатывания точек прерывания.
void handler_idle_timeout(struct mod_insn *data) {
	// Устанавливаем +1% bp от общего числа инструкций
	set_bp_auto(data, 1);
}

int handler_insn_bp_pre_helper(struct kprobe *p, struct pt_regs *regs) {
	debug_util_print_string("\nKprobes pre_handler: p->addr = ");
	debug_util_print_u64(PTR_ERR(p->addr), "%p");
	debug_util_print_string(", ip = ");
	debug_util_print_u64(regs->ip, "%x");
	debug_util_print_string(", flags = ");
	debug_util_print_u64(regs->flags, "%1x");
	handler_insn_bp_pre(regs, p->addr, &data);
	return 0;
}

struct insn * get_insn_by_addr(void *address, struct mod_insn *data) {
	int i;
	struct insn * insn = NULL;
	
	// TODO: Сделать какую-нибудь хэш табличку, чтобы побыстрее это всё.
	for (i = 0; i < data->size; i++) {
		if (data->insns[i]->kaddr == address) {
			// указатель на текущую анализируемую инструкцию
			insn = data->insns[i];
			break; // for
		}
	}
	if (insn == NULL) {
		// Мы не нашли инструкцию с таким адресом. Значит, ничего не поделаешь.
		debug_util_print_string("\nUnable to find instruction by address: ");
		debug_util_print_u64(PTR_ERR(address), "%p");
		debug_util_print_string("\n");
		return NULL;
	}
	return insn;
}

// 14) Function to handle instruction bp triggering event
/*
	- находим по адресу оригинал инструкции в *data
	- по insn и pt_regs вызываем функцию распозначания адреса памяти
	- вызов функции простановки HW bp на адрес памяти
	- установка таймера - сколько ждать, пока сработает HW bp
*/
// для KProbes нужны два хэндлера - прехэндлер, постхэндлер.
// Вообще, ещё и fault handler, но я не представляю, что он будет делать.
// Очевидно, обрабатывать какие-то эпические фейлы. =)
void handler_insn_bp_pre (struct pt_regs * pt_regs, void * address
					, struct mod_insn * data) {
	struct insn * insn = NULL;
	
	if (data->insn != NULL) {
		// вообще, мы находимся в прехэндлере. Что делать, если мы
		// уже какую-то другую инструкцию анализируем? Ну, наверное,
		// снимать текущую точку прерывания.
		disable_insn_bp(insn); // Из хендлеров только так.
		return;
	}
	
	insn = get_insn_by_addr(address, data); // seems ok
	if (insn == NULL) {
		// Мы не нашли инструкцию с таким адресом. Значит, ничего не поделаешь.
		debug_util_print_string("\nUnknown triggered instruction. Something strange happened");
		debug_util_print_string("\n");
		return;
	}		
	
	data->insn = insn;
	data->insn->pt_regs = pt_regs;
	
	// Пока там нечего вызывать...
//	get_mem_attr(data->insn);
//	set_hw_bp(data, &data->insn->addr_info);
//	
//	set_hw_timer();
//	interruptible_sleep_on(&wq);
}

void handler_insn_bp_post_helper(struct kprobe *p, struct pt_regs *regs
								, unsigned long flags) 
{
	debug_util_print_string("\nKprobes post_handler: p->addr = ");
	debug_util_print_u64(PTR_ERR(p->addr), "%p");
	debug_util_print_string(", ip = ");
	debug_util_print_u64(regs->ip, "%x");
	debug_util_print_string(", flags = "); 	
	debug_util_print_u64(regs->flags, "%1x");
//	debug_util_print_string(", data pointer: ");
//	debug_util_print_u64(PTR_ERR(&data), "%p");
//	debug_util_print_string(", insns pointer: ");
//	debug_util_print_u64(PTR_ERR(data.insns), "%p");
	handler_insn_bp_post(regs, p->addr, &data); // unset the bp
	return;
}

// 14.5) Пост хэндлер Kprobes
void handler_insn_bp_post (struct pt_regs * pt_regs, void * address
						, struct mod_insn * data) {
	if (data->insn == NULL) {
		debug_util_print_string("\nFailed to handle insn in post handler: NULL insn struct.");
		debug_util_print_string("\n");
		return;		
	}
							
	disable_insn_bp(data->insn);
	data->insn = NULL; // Очищаем текущую фунцию "под рассмотрением"
	// TODO: делать ещё очистку, если надо
	
	debug_util_print_string("\n[Post handler] The number of the rest insn bp's: ");
	debug_util_print_u64(data->bp_count, "%d");
}

int handler_insn_bp_fault_helper(struct kprobe *p, struct pt_regs *regs
								, int trapnr) {
	debug_util_print_string("\nKprobes fault_handler: p->addr = ");
	debug_util_print_u64(PTR_ERR(p->addr), "%p");
	debug_util_print_string(", ip = ");
	debug_util_print_u64(regs->ip, "%x");
	debug_util_print_string(", flags = ");
	debug_util_print_u64(regs->flags, "%1x");
	debug_util_print_string(", trap #");
	debug_util_print_u64(trapnr, "%d");
	
	//handler_insn_bp_post(regs, p->addr, &data);
	// TODO: Обрабатывать ошибку простановки bp Kprobes
	return 0;
}

void handler_hw_bp_helper(struct perf_event *bp,
						struct perf_sample_data *s_data,
						struct pt_regs *regs) {
	struct insn *insn;
	// dump_stack(); if we need to
	printk(KERN_INFO "lindacol: stack dumped from HW bp handler\n");
	insn = get_insn_by_addr(ERR_PTR(instruction_pointer(regs)), &data);
	if (insn == NULL) {
		pr_info("lindacol: unable to find instruction that triggered HW bp!");
	}
	if (data.insn->insn_hw != NULL) {
		pr_info ("lindacol: Trying to handle HW bp while it seems that another HW bp is handled.");
	}
	data.insn->insn_hw = insn;
	data.insn->insn_hw->pt_regs = regs;
	data.insn->insn_hw->is_hw = 1;
	get_mem_attr(data.insn->insn_hw);
	// в s_data->addr адрес инструкции, по нему можно найти наш insn
	// в s_data->ctx->(bp_addr, bp_len, bp_type) - та инфа, которая нам нужна.
	// TODO: найти и присвоить инструкцию data->insn->insn_hw.
	handler_hw_bp(regs, ERR_PTR(bp->attr.bp_addr), &data);
}

// 15) Function to handle HW bp triggering event
/*
	- плевать предупреждение в debug fs
	- вызов функции снятия HW и insn bp
*/
void handler_hw_bp (struct pt_regs * pt_regs, void * mem_address
	, struct mod_insn * data) {
	// Так. А по адресу нам надо узнать, а кто ж к нему обращался?
	// Не надо, в data и так всё есть.
	warning_hw(data->insn, data->insn->insn_hw);
	unset_hw_bp(data, data->insn);
	wake_up_interruptible(&wq); // Продолжаем выполнять прехэндлер KProbes
}


void handler_hw_timer_helper (unsigned long id) {
	// Вообще, у нас в id лежит адрес инструкции, которая исследовалась, когда мы
	// этот таймер запустили. Есть смысл проверить, соответствует ли id нашим ожиданиям.
	if ((struct insn *)id != data.insn) {
		pr_err("lindacol: Trying to handle timer of non-analysing instruction!");
		return;
	}
	handler_hw_timeout(&data);
}
	
// 16) Function to handle timeout hw event (with double read check)
/*
	- double read участок памяти
	- плюнуть предупреждение, если не сходится
	- вызов функции снятия HW и insn bp
*/
// Эта функция является постхэндлером KProbes (или вызывается из прехэндлера, 
// тут ещё надо подумать). Так что тут надо снять
// insn bp и hw_bp, если ещё не снята.
void handler_hw_timeout (struct mod_insn * data) {
	// расширить структуру insn данными об участке памяти (уже сделанно)
	// расширить структуру insn адресом памяти. Сделано.
	// Надо сравнить size байт новой памяти со старым значением.
	
	int i;
	char * mem_new;
	mem_new = (char*) data->insn->addr_info.address;
	for (i = 0; i < data->insn->addr_info.size; i++) {
		if (data->insn->addr_info.content[i] != mem_new[i]) {
			warning_double_read(data->insn);
		}
	}
	
	// Проверить, не поставлена ли HW bp.
	if (data->insn->is_hw) {
		unset_hw_bp(data, data->insn); // А можно вообще сделать, чтобы она же 
		// и проверяла, нужно что снимать или нет. Хотя, тогда непонятно,
		// как проверять, ошибочно мы вызвали или нет.
	}
	
	wake_up_interruptible(&wq); // Продолжаем выполнять прехэндлер KProbes
}

// 17) Function to unset current breakpoints and setting new
/*
	- снять HW bp
	- снять insn bp
	- вызвать функцию простановки нужного количества новых bp
*/
void unset_cur_bp_and_set_new (struct mod_insn * data) {
	unset_hw_bp(data, data->insn);
	unset_insn_bp(data->insn);
	set_bp_auto(data, 0);
}

// 18) Function to deinitialize data collider fucntionality
/*
	- снять все точки прерывания
	- остановить все таймеры
*/
void data_collider_fini(void) {
	data_collider_fini_helper(&data);
}

void data_collider_fini_helper (struct mod_insn * data) {
	int i;
	for (i = 0; i < data->size; i++) {
		if (data->insns[i]->is_hw) {
			unset_hw_bp(data, data->insns[i]);
		}
		if (data->insns[i]->is_bp) {
			unset_insn_bp(data->insns[i]);
		}
	}
}
