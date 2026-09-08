<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { workspaceRequest } from '../api/workspaces'
const capacity = ref<{max_devices: number | null; used_devices: number} | null>(null)
const error = ref('')
onMounted(async () => { try { capacity.value = await workspaceRequest('/capacity') } catch(e) { error.value = e instanceof Error ? e.message : String(e) } })
</script>
<template><section class="console-panel"><h2>Capacidade do espaço</h2><p v-if="capacity">{{ capacity.used_devices }} números cadastrados · {{ capacity.max_devices === null ? 'sem limite configurado' : `${capacity.max_devices} vagas` }}</p><p v-if="error" class="alert">{{ error }}</p></section></template>
