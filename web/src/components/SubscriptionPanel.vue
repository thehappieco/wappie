<script setup lang="ts">
import { t } from '../ui/i18n'
import { onMounted, ref } from 'vue'
import { workspaceRequest } from '../api/workspaces'
const capacity = ref<{max_devices: number | null; used_devices: number} | null>(null)
const error = ref('')
onMounted(async () => { try { capacity.value = await workspaceRequest('/capacity') } catch(e) { error.value = e instanceof Error ? e.message : String(e) } })
</script>
<template><section class="console-panel"><h2>{{ t('Capacidade do espaço') }}</h2><p v-if="capacity">{{ t('{v0} números cadastrados · {v1}', { v0: capacity.used_devices, v1: capacity.max_devices === null ? t('sem limite configurado') : `${capacity.max_devices} vagas` }) }}</p><p v-if="error" class="alert">{{ error }}</p></section></template>
