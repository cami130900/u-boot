/**
 * @name Test Memcpy
 * @description Cerchiamo tutte le memcpy per vedere se CodeQL funziona
 * @kind problem
 * @problem.severity warning
 * @id c/test-memcpy
 */

import cpp

from FunctionCall call
where call.getTarget().getName() = "memcpy"
select call, "Ho trovato una chiamata a memcpy!"
