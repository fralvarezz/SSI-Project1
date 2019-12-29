package caminosantiago;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * @author ribadas
 */
public class Paquete {

    private Map<String, Bloque> bloques;

    public Paquete() {
        this.bloques = new HashMap<String, Bloque>();
    }

    public Paquete(Map<String, Bloque> bloques) {
        this.bloques = bloques;
    }

    private Bloque getBloque(String nombreBloque) {
        Bloque result = null;
        if (this.bloques != null) {
            String nombreBloqueNormalizado = normalizarNombre(nombreBloque);
            result = this.bloques.get(nombreBloqueNormalizado);
        }
        return result;
    }

    public byte[] getContenidoBloque(String nombreBloque) {
	Bloque bloque = getBloque(nombreBloque);
	if (bloque != null) {
		return bloque.getContenido();
	} else {
		return null;
	}
    }


    private void anadirBloque(Bloque bloque) {
	this.anadirBloque(bloque.getNombre(), bloque);
    }


    public void anadirBloque(String nombre, byte[] contenido) {
	this.anadirBloque(new Bloque(nombre, contenido));
    }

    private void anadirBloque(String nombreBloque, Bloque bloque) {
        if (this.bloques == null) {
            this.bloques = new HashMap<String, Bloque>();
        }
        String nombreBloqueNormalizado = normalizarNombre(nombreBloque);
        this.bloques.put(nombreBloqueNormalizado, bloque);
    }

    public void actualizarBloque(String nombre, byte[] contenido) {
        Bloque bloque = new Bloque(nombre, contenido);
        if (this.bloques != null && this.bloques.containsKey(bloque.getNombre())) {
            this.bloques.replace(bloque.getNombre(), bloque);
        }
        else {
	    this.anadirBloque(bloque.getNombre(), bloque);
       }
    }


    public void eliminarBloque(String nombreBloque) {
        if (this.bloques != null) {
            if (this.bloques.containsKey(nombreBloque)) {
                this.bloques.remove(nombreBloque);
            }
        }
    }

    public List<String> getNombresBloque() {
        List<String> result = new ArrayList<String>(this.bloques.keySet());
        
        Collections.sort(result);
        return result;
    }

    private String normalizarNombre(String nombreBloque) {
        String result = nombreBloque.trim().replaceAll(" ", "_").toUpperCase();
        return result;
    }
}
