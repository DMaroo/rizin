// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static void fix_arm_thumb_symbol(RzBinElfSymbol *symbol) {
	symbol->bits = 16;

	if (Elf_(rz_bin_elf_is_thumb_addr)(symbol->vaddr)) {
		symbol->vaddr--;
	}

	if (Elf_(rz_bin_elf_is_thumb_addr)(symbol->paddr)) {
		symbol->paddr--;
	}
}

static bool start_a_sequence_of_instruction(RzBinElfSymbol *symbol) {
	return strlen(symbol->name) > 3 && rz_str_startswith(symbol->name, "$a.");
}

static bool start_a_sequence_of_thumb_instruction(RzBinElfSymbol *symbol) {
	return strlen(symbol->name) > 3 && rz_str_startswith(symbol->name, "$t.");
}

static bool start_a_sequence_of_data(RzBinElfSymbol *symbol) {
	return strlen(symbol->name) > 3 && rz_str_startswith(symbol->name, "$d.");
}

bool Elf_(rz_bin_elf_is_arm_binary)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);
	return (bin->ehdr.e_machine == EM_ARM || bin->ehdr.e_machine == EM_AARCH64);
}

bool Elf_(rz_bin_elf_is_thumb_addr)(ut64 addr) {
	return addr != UT64_MAX && addr & 1;
}

void Elf_(rz_bin_elf_fix_arm_object)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL ut64 *paddr, RZ_NONNULL ut64 *vaddr, RZ_NONNULL int *bits) {
	rz_return_if_fail(bin && paddr && vaddr && bits);

	*bits = bin->bits;

	if (*bits == 64) {
		return;
	}

	*bits = 32;

	if (*paddr == UT64_MAX) {
		return;
	}

	if (Elf_(rz_bin_elf_is_thumb_addr)(*vaddr)) {
		*vaddr -= 1;
		*bits = 16;
	}

	if (Elf_(rz_bin_elf_is_thumb_addr)(*paddr)) {
		*paddr -= 1;
		*bits = 16;
	}
}

void Elf_(rz_bin_elf_fix_arm_symbol)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RzBinElfSymbol *symbol) {
	rz_return_if_fail(bin && symbol);

	if (!Elf_(rz_bin_elf_is_arm_binary)(bin) || !symbol->name) {
		return;
	}

	if (start_a_sequence_of_instruction(symbol)) {
		symbol->bits = 32;
	} else if (start_a_sequence_of_thumb_instruction(symbol)) {
		fix_arm_thumb_symbol(symbol);
	} else if (!start_a_sequence_of_data(symbol)) {
		rz_bin_elf_fix_arm_object_dispatch(bin, symbol);
	}
}
