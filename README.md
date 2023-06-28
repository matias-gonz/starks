# starks

Se quiere probar la validez de un programa que calcula $2^{8^{20}}$. Se proponen dos estrategias:

1. $a_{n+1} = a_n^8$ y $a_0 = 2$
2. $a_{n+1} = a_n^2$ y $a_0 = 2$

## Primer estrategia:

* Se deben calcular 21 terminos.
* Luego el generador $g$ debe ser de orden 32.
* Con un blowup de 8, el dominio pasa a ser de 256 elementos.

### Restricciones

**Restricción de contorno:** $f(x) = 2$

**Restricción de succinctness:** $\frac{f(gx) - f^8(x)}{\prod_{i=0}^{19}x - g^i}$


## Segunda estrategia:
* Se deben calcular 61 terminos.
* Luego el generador $g$ debe ser de orden 64.
* Con un blowup de 8, el dominio pasa a ser de 512 elementos.

### Restricciones

**Restricción de contorno:** $f(x) = 2$

**Restricción de succinctness:** $\frac{f(gx) - f^8(x)}{\prod_{i=0}^{59}x - g^i}$

## Resultados

|       Caso      | Tamaño de prueba | Tiempo de cálculo | Tamaño de traza |
|:---------------:|:----------------:|:----------------:|:-----------------:|
|         1       |      16584       |     56.546ms     |        21         |
|         2       |      13416       |     89.624ms     |        61         |

Se observa que la primer estraegia es más eficiente en cuanto a tiempo de cálculo y tamaño de traza. Sin embargo, la segunda estrategia es más eficiente en cuanto a tamaño de prueba.

Siempre depende del caso de uso, pero generalmente la memoria es barata y se quieren maximizar la cantidad de pruebas que se pueden hacer en un tiempo determinado. Por lo tanto, la primer estrategia es la más conveniente.

El tiempo de verificación debería ser bajo para ambos casos.
