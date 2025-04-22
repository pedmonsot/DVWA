# Análisis de Vulnerabilidades en DVWA (Damn Vulnerable Web Application

## RA 3.2

Damn Vulnerable Web Application (DVWA) es una aplicación web diseñada intencionalmente con vulnerabilidades de seguridad para fines educativos. Su objetivo es permitir a desarrolladores y profesionales de ciberseguridad practicar técnicas de pentesting en un entorno controlado y seguro. DVWA incluye múltiples retos de seguridad clasificados por nivel de dificultad, enfocados en vulnerabilidades comunes como SQL Injection, XSS, CSRF, entre otras.

![general](https://github.com/user-attachments/assets/05639006-28cc-40c9-bd71-fadfae4e744b)

## Brute Force
**LOW**

Se ha utilizado la herramienta Wfuzz, similar a Hydra, para realizar un ataque de fuerza bruta y extraer contraseñas, con el comando:
```
wfuzz -c -z file,users.txt -z file,/home/crystal/secLists/Passwords/probable-v2-top1575.txt -b 'security=medium; PHPSESSID=cnavat4393qp4r1k36qp7h3ec' \
'http://127.0.0.1/dvwa/vulnerabilities/brute/index.php?username=FUZZ&password=FUZZ&Login=Login'
```
![general](https://github.com/pedmonsot/DVWA/blob/main/Images/BF1.png)

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/BF2.png)

**MEDIUM**

Teniendo el DVWA configurado con el nivel de seguridad en 'Medium'. Usando la misma herramienta, la contraseña es la misma que usa en el nivel 'Low', pero nos fijamos en la longitud de resultado para la elección.

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/BF3.png)

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/BF4.png)

## Command Injection
**LOW**

Este nos hace ping a la IP que le marcamos y, si le colocamos dos "&&", no ejecuta lo siguiente comando que tenga. Así que probamos con la siguiente sintaxis.
```
127.0.0.1 && ls
```
![general](https://github.com/pedmonsot/DVWA/blob/main/Images/CI1.png)

**MEDIUM**

Como vemos en el código, ya nos deja poner doble "&". Aquí nos sustituye los "&&" por un espacio en blanco y no deja ejecutar un comando después, así que se usa un solo "&".

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/CI2.png)

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/CI3.png)

## CSFR
**LOW**

Después de cambiar la contraseña, nos aparece en la barra de arriba una URL que se puede manipular desde ahí mismo. Tiene algo parecido a esto, ?password_new=password&password_conf=password&Change=Change, pudiéndose modificar directamente desde la propia URL.

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/CSFR1.png)

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/CSFR2.png)

**MEDIUM**

En el nivel "medium" ya no podemos modificar la contraseña directamente desde la URL, pero sí podemos usar una vulnerabilidad de tipo XSS para ejecutar un script. Por ejemplo, podemos insertar una imagen maliciosa que cargue una URL como la anterior. Sería algo así:
```
<img src="http://localhost:8080/vulnerabilities/csrf/?password_new=admin2&password_conf=admin2&Change=Change#" style="display:none">
```
![general](https://github.com/pedmonsot/DVWA/blob/main/Images/CSFR3.png)

## File Inclusion
**LOW**

Es bastante similar al CSRF, pero en este caso lo que hacemos es manipular la URL para introducir una ruta. El sistema la acepta sin validaciones, lo que nos permite acceder a archivos del servidor.
```
http://localhost:8080/vulnerabilities/fi/?page=../../robots.txt
```
Con esta URL, estamos intentando leer el archivo robots.txt que está fuera del directorio permitido, usando la técnica de path traversal. Básicamente, vamos subiendo directorios con los ../ hasta llegar al archivo que queremos.

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/FI1.png)

**MEDIUM**

Como podemos ver el código en la imagen, ahora ya tenemos bloqueado el acceso a rutas comunes. Nos restringe el uso de ```https``` y de los ```..``` (dobles puntos), como se muestra también en la imagen.

Sin embargo, muchos servidores no validan correctamente si la dirección cambia un poco. Por ejemplo, en lugar de seguir el patrón clásico ```../../```, se puede usar algo como ```...//...//```, y en algunos casos eso también funciona para hacer path traversal. Es una forma de evadir los filtros más básicos.

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/FI2.png)

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/FI3.png)

## File Upload
**LOW**

En esta parte, subimos un archivo .php que contiene un backdoor, en este caso el conocido AK-74 Web Shell. La subida del archivo fue exitosa, como se puede ver en la primera imagen, donde aparece el mensaje:
```
../../hackable/uploads/test.php successfully uploaded!
```
![general](https://github.com/pedmonsot/DVWA/blob/main/Images/FU1.png)

Una vez subido, copiamos la ruta que nos muestra y la pegamos directamente en la barra del navegador. La URL quedaría algo así:
```
http://localhost:8080/vulnerabilities/upload/../../hackable/uploads/test.php
```
![general](https://github.com/pedmonsot/DVWA/blob/main/Images/FU2.png)

Esto nos permite ejecutar el archivo PHP que acabamos de subir, a pesar de que esté fuera del directorio normal de ejecución, gracias a una vulnerabilidad de tipo File Upload combinada con Path Traversal.

Al hacerlo, se ejecuta el web shell AK-74, lo cual nos da acceso total al servidor. Desde ahí podemos:

- Navegar entre carpetas del servidor (/var/www/html)

- Ver y editar archivos

- Eliminar archivos

- Ejecutar comandos
  
![general](https://github.com/pedmonsot/DVWA/blob/main/Images/FU3.png)

**MEDIUM**

En esta prueba, intentamos subir nuevamente el archivo malicioso ```test.php```, pero esta vez el sistema nos muestra un mensaje de error indicando que solo se aceptan imágenes JPEG o PNG, como se ve en la primera imagen:

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/FU4.png)

Para intentar evadir esta restricción, simplemente le cambiamos la extensión al archivo usando el comando cp, como se muestra en la terminal de la segunda imagen:

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/FU5.png)

Este cambio engaña al sistema, ya que solo verifica la extensión del archivo y no el contenido real. Sin embargo, si inspeccionáramos con herramientas como ```xxd```, veríamos que los magic numbers siguen indicando que el archivo es un PHP, no una imagen válida. Aun así, la validación del servidor no lo detecta y lo deja pasar.

En la tercera imagen se confirma que el archivo fue subido exitosamente, a pesar de seguir siendo un .php por dentro:

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/FU6.png)

## SQL Injection
**LOW**

Si miramos el código fuente, podemos notar que el parámetro id que recibe la aplicación se inserta directamente en la consulta SQL sin ninguna validación ni escape de caracteres. La consulta queda así:

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/SQLI2.png)

```
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```
Esto nos da la posibilidad de manipular la consulta desde el campo "User ID" en la aplicación. Al ingresar el siguiente payload:
```
' UNION SELECT user, password FROM users;-- -
```
logrando modificar la consulta original. Este ataque funciona de la siguiente manera:

``'`` : Cierra la comilla que abre la condición original ``user_id = '$id'``.

``UNION SELECT user, password FROM users``: Añade una nueva consulta que extrae los nombres de usuario y contraseñas de la tabla users.

``-- -`` : Comenta el resto de la consulta original para evitar errores de sintaxis.

La aplicación ejecuta la consulta inyectada y nos muestra los datos de todos los usuarios registrados en la base de datos, incluyendo sus contraseñas. Esto sucede porque la aplicación no valida correctamente la entrada del usuario ni utiliza consultas preparadas, dejando la puerta abierta a este tipo de ataques.

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/SQLI1.png)

**MEDIUM**

En el nivel "medium", la idea es inyectar el código malicioso directamente desde el código fuente de la página, modificando el valor de las opciones del <select> que controla el parámetro id. En la primera imagen se ve cómo se añade manualmente una opción con el payload malicioso:

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/SQLI3.png)

Sin embargo, al hacer clic en “Submit” desde Google Chrome, la página simplemente se recarga y no ejecuta correctamente la inyección, probablemente porque Chrome normaliza o corrige el valor enviado en el formulario, teniendo el mmismo resultado en Firefow, por lo cual se decidió probar con el nivel "high".

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/SQLI4.png)

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/SQLI5.png)

**HIGH**

En el nivel "high" de la vulnerabilidad SQL Injection, el comportamiento de la aplicación cambia ligeramente con respecto a los niveles anteriores. Ahora, al hacer clic en el enlace para cambiar el ID, se nos abre una nueva ventana emergente, donde debemos ingresar el valor del Session ID.

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/SQLI7.png)

Si analizamos el código fuente del backend, vemos que el valor ya no se recoge desde ``$_POST``, sino que se toma desde la variable de sesión ``$_SESSION['id']``, lo que indica que el dato ingresado se guarda y persiste entre sesiones.

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/SQLI6.png)

Este código sigue funcionando el payload del "low" porque el input se inserta directamente en la consulta SQL sin validaciones ni uso de consultas preparadas. Como resultado, al enviarlo desde la ventana emergente, se guarda en la sesión y la aplicación ejecuta la inyección exitosamente, mostrando los datos de todos los usuarios y contraseñas, tal como se ve en el panel principal.

## SQL Injection (Blind)
**LOW**

En el nivel "Blind" de SQL Injection, probamos con el payload:
```
1' AND sleep(5)#
```
Aunque el mensaje devuelto es ``"User ID is MISSING from the database"``, si el servidor tarda en responder, sabemos que la inyección fue exitosa. Esto indica que, aunque no se muestran datos directamente, sí se está ejecutando código en la base de datos.

Este tipo de inyección se basa en medir el tiempo de respuesta para confirmar la vulnerabilidad, y como se ve en la imagen, el código se inyecta correctamente.

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/SQLIB1.png)

Y como en el ejercicio anterior he tenido problemas con el cambio de código desde el navegador realizazo el high.  

**HIGH**

En este caso realizando SQL Injection pero a través de una cookie, específicamente la cookie id. Desde la ventana emergente.

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/SQLIB2.png)

Luego de enviarlo, se puede ver en las herramientas del navegador que el valor de la cookie id ha sido modificado correctamente y está codificado en URL. Aunque en pantalla la app solo muestra el mensaje ``'"User ID is MISSING from the database"``, el comportamiento del servidor, esperando 5 segundos antes de responder, confirma que la inyección se está ejecutando correctamente en segundo plano.

Este retraso es una señal clara de que la consulta SQL fue manipulada con éxito, aunque no se obtenga información directamente.

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/SQLIB3.png)

## XSS Reflected
**LOW**

En este caso del tipo XSS reflected. El código fuente muestra que el valor del parámetro name se inserta directamente en el HTML sin ningún tipo de validación o sanitización.

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/xss1.png)

Así que introducimos el siguiente payload:
```
?name=<script>alert("XSS")</script>
```
![general](https://github.com/pedmonsot/DVWA/blob/main/Images/xss2.png)

El navegador interpreta el código JavaScript, ejecutando una alerta con el texto "XSS". Esto demuestra que es posible inyectar y ejecutar scripts maliciosos a través del parámetro name.

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/xss3.png)

**MEDIUM**

En el nivel medium de la vulnerabilidad Reflected XSS, el código intenta prevenir ataques eliminando cualquier aparición exacta de ``<script>`` en el parámetro name.

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/xss4.png)

Como se ve en la segunda imagen, se puede usar un payload ofuscado como:
```
<scr<script>ipt>alert("You have been hacked")</script>
```
![general](https://github.com/pedmonsot/DVWA/blob/main/Images/xss5.png)

El primer ``<script>`` es eliminado por la función ``str_replace``, pero al quedar el resto intacto ``<script>ipt> se convierte nuevamente en <script>``, el navegador lo interpreta como código válido.

El script se ejecuta correctamente y lanza una alerta, demostrando que la protección implementada es insuficiente.

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/xss6.png)

## XSS Stored
**LOW**

A diferencia del XSS reflected, donde el script se ejecuta al momento de enviarlo, en este caso el código malicioso se guarda en la base de datos y se ejecuta cada vez que alguien carga esa página.
```
<script>alert("Got it")</script>
```
![general](https://github.com/pedmonsot/DVWA/blob/main/Images/XSSS1.png)

Como se ve en la imagen, el mensaje aparece en un ``alert``, confirmando que el script fue almacenado y luego ejecutado al visualizar el contenido.

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/XSSS2.png)

**MEDIUM**

En el nivel medium de Stored XSS, el sistema intenta filtrar entradas maliciosas, pero de forma muy básica, similar a lo que se ve en el XSS reflected. En este caso, el filtrado elimine coincidencias exactas de la etiqueta ``<script>``, sin tener en cuenta variaciones de formato.

Por eso, como se muestra en la imagen, se puede ofuscar el payload usando mayúsculas o agregando espacios dentro de la etiqueta:
```
<SCRIPT>document.write("Hacked!!")</S cr i p t>
```
Esta variante evade el filtro simple y logra ejecutar el código malicioso. El script queda almacenado en la base de datos, y cada vez que se visualiza el mensaje, se ejecuta, mostrando el texto “Hacked!!” en la página. Esto confirma que el sistema sigue siendo vulnerable, aunque tenga medidas de protección mínimas.

![general](https://github.com/pedmonsot/DVWA/blob/main/Images/XSSS3.png)
