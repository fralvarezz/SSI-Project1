/**
 *
 * @author ifmartinez_ESEI
 */
public class Peregrino {

    private String nombre;
    private String dni;
    private String domicilio;
    private String fechaCreacion;
    private String lugarCreacion;
    private String motivacion;
    
    public Peregrino(String nombre, String dni, String domicilio, String fechaCreacion, String lugarCreacion, String motivacion) {
        this.nombre = nombre;
        this.dni = dni;
        this.domicilio = domicilio;
        this.fechaCreacion = fechaCreacion;
        this.lugarCreacion = lugarCreacion;
        this.motivacion = motivacion;
    }

    public String getNombre() {
        return nombre;
    }

    public String getDni() {
        return dni;
    }

    public String getDomicilio() {
        return domicilio;
    }

    public String getFechaCreacion() {
        return fechaCreacion;
    }

    public String getLugarCreacion() {
        return lugarCreacion;
    }

    public String getMotivacion() {
        return motivacion;
    }
    
    

}
